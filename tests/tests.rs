use std::time::Duration;

use actix_oidc_token::{AccessToken, TokenRequest};

#[actix_rt::test]
async fn token() {
  jonases_tracing_util::init_logger();

  let request = TokenRequest::password_with_client_id(
    "admin".to_owned(),
    "admin".to_owned(),
    "admin-cli".to_owned(),
  );

  request.send(
    "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
  )
  .await
  .unwrap();
}

#[actix_rt::test]
async fn access_token() {
  jonases_tracing_util::init_logger();

  let tr = TokenRequest::password_with_client_id(
    "admin".to_owned(),
    "admin".to_owned(),
    "admin-cli".to_owned(),
  );

  let at = AccessToken::new(
    "http://localhost:8080/auth/realms/master/protocol/openid-connect/token".to_owned(),
    tr
  );

  // delay so that task that gets the token response has time to
  // finish
  actix_web::rt::time::delay_for(Duration::from_secs(1)).await;

  at.bearer().await.unwrap();
}
