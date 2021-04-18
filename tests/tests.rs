use actix_oidc_token::TokenRequest;

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
