use azure_security_keyvault::KeyvaultClient;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};

#[allow(dead_code)]
pub struct ApiKey(String);

/// Returns true if `key` is a valid API key string.
async fn is_valid(key: &str) -> bool {
	let azure_credentials = azure_identity::create_credential().unwrap();
	let client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", azure_credentials).unwrap();
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
			0 => Outcome::Error((Status::BadRequest, ApiKeyError::Missing)),
			1 if is_valid(keys[0]).await => Outcome::Success(Self(keys[0].to_string())),
			1 => Outcome::Error((Status::BadRequest, ApiKeyError::Invalid)),
			_ => Outcome::Error((Status::BadRequest, ApiKeyError::BadCount)),
		}
	}
}
