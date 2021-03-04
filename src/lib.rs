#![feature(try_trait)]

use actix_web::client::Client;

use actix_web_httpauth::headers::authorization::Bearer;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde::Deserialize;

use std::option::NoneError;

pub mod error {
  use actix_web::client::{SendRequestError, JsonPayloadError};

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

pub struct AccessToken {
  token_response: Option<TokenResponse>,
  endpoint: String,
  token_request: TokenRequest,
}

impl AccessToken {
  pub fn new(
    endpoint: String,
    token_request: TokenRequest,
  ) -> AccessToken {
    AccessToken {
      token_response: None,
      endpoint,
      token_request,
    }
  }

  pub async fn get_token(
    &mut self,
    client: &Client,
  ) -> Result<(), error::Error> {
    self.token_response = Some(
      client
        .post(&self.endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send_form(&self.token_request)
        .await?
        .json()
        .await?,
    );

    Ok(())
  }

  pub fn expires_in(&self) -> Option<i64> {
    let token_response = self.token_response.as_ref()?;
    Some(token_response.expires_in)
  }

  pub fn access_token(&self) -> Option<String> {
    let token_response = self.token_response.as_ref()?;
    Some(token_response.access_token.clone())
  }

  pub fn bearer(&self) -> Result<Bearer, NoneError> {
    Ok(Bearer::new(self.access_token()?))
  }
}

pub enum TokenRequest {
  ClientCredentials {
    client_id: String,
    client_secret: String,
  },
  Password {
    username: String,
    password: String,
  }
}

impl Serialize for TokenRequest {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    match self {
      TokenRequest::ClientCredentials {
        client_id,
        client_secret,
      } => {
        let mut s = serializer.serialize_map(Some(3))?;
        s.serialize_entry("client_id", client_id)?;
        s.serialize_entry("client_secret", client_secret)?;
        s.serialize_entry("grant_type", "client_credentials")?;
        s.end()
      }
      TokenRequest::Password {
        username,
        password,
      } => {
        let mut s = serializer.serialize_map(Some(3))?;
        s.serialize_entry("username", username)?;
        s.serialize_entry("password", password)?;
        s.serialize_entry("grant_type", "password")?;
        s.end()
      }
    }
  }
}

#[derive(Deserialize)]
pub struct TokenResponse {
  pub access_token: String,
  pub expires_in: i64,
}

#[cfg(test)]
mod tests {
  use super::TokenRequest;

  use serde_urlencoded::to_string;

  #[test]
  fn serializing_client_credentials_token_request_to_url_encoded() {
    let token_request = TokenRequest::ClientCredentials {
      client_id: String::from("some id"),
      client_secret: String::from("some secret"),
    };

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "client_id=some+id&client_secret=some+secret&",
        "grant_type=client_credentials"
      )
    );
  }

  #[test]
  fn serializing_password_token_request_to_url_encoded() {
    let token_request = TokenRequest::Password {
      username: String::from("some name"),
      password: String::from("some password"),
    };

    assert_eq!(
      to_string(token_request).unwrap(),
      concat!(
        "username=some+name&password=some+password&",
        "grant_type=password"
      )
    );
  }
}
