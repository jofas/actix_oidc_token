#![feature(try_trait)]

use actix_web::client::Client;

use actix_web_httpauth::headers::authorization::Bearer;

use serde::{Deserialize, Serialize};

use tokio::sync::RwLock;

use tracing::{event, Level};

use std::option::NoneError;
use std::sync::Arc;
use std::time::Duration;

pub mod error {
  use actix_web::client::{JsonPayloadError, SendRequestError};

  #[derive(Debug)]
  pub enum Error {
    SendRequestError(SendRequestError),
    JsonPayloadError(JsonPayloadError),
  }

  impl From<SendRequestError> for Error {
    fn from(e: SendRequestError) -> Self {
      Self::SendRequestError(e)
    }
  }

  impl From<JsonPayloadError> for Error {
    fn from(e: JsonPayloadError) -> Self {
      Self::JsonPayloadError(e)
    }
  }
}

#[derive(Clone)]
pub struct AccessToken {
  inner: Arc<RwLock<InnerAccessToken>>,
}

impl AccessToken {
  pub fn new(endpoint: String, token_request: TokenRequest) -> Self {
    let inner = InnerAccessToken::new(endpoint, token_request);

    AccessToken {
      inner: Arc::new(RwLock::new(inner)),
    }
  }

  pub async fn periodically_refresh(self) -> Self {
    let client = Client::builder().disable_timeout().finish();

    self.refresh_token(&client).await;

    let res = self.clone();

    actix_web::rt::spawn(async move {
      loop {
        actix_web::rt::time::delay_for({
          let expires_in = match self.inner.read().await.expires_in()
          {
            Some(expires_in) => expires_in as f64,
            None => 60.,
          };

          Duration::from_secs_f64(expires_in * 0.98_f64)
        })
        .await;

        self.refresh_token(&client).await;
      }
    });

    res
  }

  pub async fn refresh_token(&self, client: &Client) {
    self.log_token_request(
      self.inner.write().await.get_token(client).await,
    );
  }

  pub async fn bearer(&self) -> Result<Bearer, NoneError> {
    self.inner.read().await.bearer()
  }

  pub async fn token_response(&self) -> Option<TokenResponse> {
    self.inner.read().await.token_response()
  }

  fn log_token_request(
    &self,
    token_request_result: Result<(), error::Error>,
  ) {
    if let Err(e) = token_request_result {
      event!(
        Level::ERROR, msg = "could not refresh token", error = ?e
      );
    }
  }
}

struct InnerAccessToken {
  token_response: Option<TokenResponse>,
  endpoint: String,
  token_request: TokenRequest,
}

impl InnerAccessToken {
  fn new(
    endpoint: String,
    token_request: TokenRequest,
  ) -> InnerAccessToken {
    InnerAccessToken {
      token_response: None,
      endpoint,
      token_request,
    }
  }

  async fn get_token(
    &mut self,
    client: &Client,
  ) -> Result<(), error::Error> {
    self.token_response = Some(
      client
        .post(&self.endpoint)
        .send_form(&self.token_request)
        .await?
        .json()
        .await?,
    );

    Ok(())
  }

  fn expires_in(&self) -> Option<i64> {
    let token_response = self.token_response.as_ref()?;
    Some(token_response.expires_in)
  }

  fn access_token(&self) -> Option<String> {
    let token_response = self.token_response.as_ref()?;
    Some(token_response.access_token.clone())
  }

  fn token_response(&self) -> Option<TokenResponse> {
    self.token_response.clone()
  }

  fn bearer(&self) -> Result<Bearer, NoneError> {
    Ok(Bearer::new(self.access_token()?))
  }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "grant_type")]
#[serde(rename_all = "snake_case")]
pub enum TokenRequest {
  ClientCredentials {
    client_id: String,
    client_secret: String,
  },
  Password {
    username: String,
    password: String,
    client_id: Option<String>,
  },
  RefreshToken {
    refresh_token: String,
    client_id: Option<String>,
  },
}

impl TokenRequest {
  pub fn client_credentials(
    client_id: String,
    client_secret: String,
  ) -> Self {
    Self::ClientCredentials {
      client_id: client_id,
      client_secret: client_secret,
    }
  }

  pub fn password(username: String, password: String) -> Self {
    Self::Password {
      username: username,
      password: password,
      client_id: None,
    }
  }

  pub fn password_with_client_id(
    username: String,
    password: String,
    client_id: String,
  ) -> Self {
    Self::Password {
      username,
      password,
      client_id: Some(client_id),
    }
  }

  pub fn refresh_token(refresh_token: String) -> Self {
    Self::RefreshToken {
      refresh_token,
      client_id: None,
    }
  }

  pub fn refresh_token_with_client_id(
    refresh_token: String,
    client_id: String,
  ) -> Self {
    Self::RefreshToken {
      refresh_token,
      client_id: Some(client_id),
    }
  }

  pub fn add_client_id(self, client_id: String) -> Self {
    match self {
      Self::Password {
        username,
        password,
        client_id: _,
      } => {
        Self::password_with_client_id(username, password, client_id)
      }
      Self::RefreshToken {
        refresh_token,
        client_id: _,
      } => {
        Self::refresh_token_with_client_id(refresh_token, client_id)
      }
      other => other,
    }
  }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct TokenResponse {
  pub access_token: String,
  pub expires_in: i64,
  pub refresh_token: Option<String>,
  pub refresh_expires_in: Option<i64>,
}

impl TokenResponse {
  pub fn bearer(&self) -> Bearer {
    Bearer::new(self.access_token.clone())
  }
}

#[cfg(test)]
mod tests {
  use super::TokenRequest;

  use serde_urlencoded::to_string;

  #[test]
  fn serializing_client_credentials_token_request_to_url_encoded() {
    let token_request = TokenRequest::client_credentials(
      String::from("some id"),
      String::from("some secret"),
    );

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "grant_type=client_credentials",
        "&client_id=some+id&client_secret=some+secret",
      )
    );
  }

  #[test]
  fn serializing_password_token_request_to_url_encoded() {
    let token_request = TokenRequest::password(
      String::from("some name"),
      String::from("some password"),
    );

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "grant_type=password",
        "&username=some+name&password=some+password",
      )
    );
  }

  #[test]
  fn serializing_password_token_request_with_id_to_url_encoded() {
    let token_request = TokenRequest::password_with_client_id(
      String::from("some name"),
      String::from("some password"),
      String::from("some id"),
    );

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "grant_type=password&username=some+name",
        "&password=some+password&client_id=some+id",
      )
    );
  }

  #[test]
  fn serializing_refresh_token_request_to_url_encoded() {
    let token_request =
      TokenRequest::refresh_token(String::from("token"));

    assert_eq!(
      to_string(token_request).unwrap(),
      "grant_type=refresh_token&refresh_token=token".to_owned(),
    );
  }

  #[test]
  fn serializing_refresh_token_request_with_id_to_url_encoded() {
    let token_request = TokenRequest::refresh_token_with_client_id(
      String::from("token"),
      String::from("some id"),
    );

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "grant_type=refresh_token&refresh_token=token",
        "&client_id=some+id",
      )
    );
  }
}
