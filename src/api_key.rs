use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use std::sync::Arc;

pub struct ApiKey(String);

/// Returns true if `key` is a valid API key string.
async fn is_valid(key: &str) -> bool {
        let azure_credentials = ImdsManagedIdentityCredential::default();
	let client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap();
	let api_key = client.secret_client().get("workbook-api-key").await.unwrap().value;
	key == api_key
}

#[derive(Debug)]
pub enum ApiKeyError {
	BadCount,
	Missing,
	Invalid,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey {
	type Error = ApiKeyError;

	async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
		let keys: Vec<_> = request.headers().get("Authorization").collect();
		match keys.len() {
			0 => Outcome::Failure((Status::BadRequest, ApiKeyError::Missing)),
			1 if is_valid(keys[0]).await => Outcome::Success(ApiKey(keys[0].to_string())),
			1 => Outcome::Failure((Status::BadRequest, ApiKeyError::Invalid)),
			_ => Outcome::Failure((Status::BadRequest, ApiKeyError::BadCount)),
		}
	}
}