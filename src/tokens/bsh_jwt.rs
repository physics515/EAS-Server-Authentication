#![warn(missing_docs)]
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use playwright::api::Cookie as PlaywrightCookie;
use rocket::request::Outcome;
use rocket::request::{self, FromRequest, Request};
use serde::{Deserialize, Serialize};

///
/// # BSH JSON Web Token (JWT) Claims
/// This is the JSON Web Token (JWT) claims that will be included in the BSH JSON Web Token (JWT).
/// The BSH JSON Web Token (JWT) is use to store cookies that are used by Playwright to authenticate to the BSH website.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSHJWTTokenClaims {
	/// The expiration time of the token.
	pub exp: u64,
	/// The cookies that are used by Playwright to authenticate to the BSH website.
	pub bsh_cookies: Vec<PlaywrightCookie>,
}

impl Display for BSHJWTTokenClaims {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "BSHJWTTokenClaims {{ exp: {}, bsh_cookies: {:?} }}", self.exp, self.bsh_cookies)
	}
}

impl BSHJWTTokenClaims {
	///
	/// Encodes the BSHJWTTokenClaims into a JWT string.
	///
	pub async fn encode(bsh_cookies: Vec<PlaywrightCookie>) -> Result<String, String> {
		let jwt_token_claim = BSHJWTTokenClaims { exp: jsonwebtoken::get_current_timestamp() + 3600, bsh_cookies };

		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let user_token_secret = match client.secret_client().get("user-token-secret").await {
			Ok(token_secret) => token_secret,
			Err(e) => return Err(format!("Faild to get user-token-secret from Azure Key Vault: {e:?}")),
		};
		let user_token_secret = user_token_secret.value;

		let token = encode(&Header::default(), &jwt_token_claim, &EncodingKey::from_secret(user_token_secret.as_bytes()));

		match token {
			Ok(token) => Ok(token),
			Err(e) => Err(format!("Failed to encode JWT token: {e:?}")),
		}
	}

	///
	/// Decodes the JWT string into a BSHJWTTokenClaims.
	///
	pub async fn decode(token: &str) -> Result<BSHJWTTokenClaims, String> {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let user_token_secret = match client.secret_client().get("user-token-secret").await {
			Ok(token_secret) => token_secret,
			Err(e) => return Err(format!("Faild to get user-token-secret from Azure Key Vault: {e:?}")),
		};
		let key = user_token_secret.value;
		let key = DecodingKey::from_secret(key.as_bytes());
		let validation = Validation::default();
		let claims = decode::<BSHJWTTokenClaims>(token, &key, &validation);
		match claims {
			Ok(claims) => Ok(BSHJWTTokenClaims { exp: claims.claims.exp, bsh_cookies: claims.claims.bsh_cookies }),
			Err(e) => Err(format!("Failed to decode JWT token: {e:?}")),
		}
	}
}

///
/// # BSH JSON Web Token (JWT) Request Guard
/// This is the BSH JSON Web Token (JWT) request guard. If the route requires a BSH JSON Web Token (JWT) to be present, then this guard will be used to pull the JWT from the server and include it with the request.
///
#[rocket::async_trait]
impl<'r> FromRequest<'r> for BSHJWTTokenClaims {
	type Error = std::convert::Infallible;

	async fn from_request(_request: &'r Request<'_>) -> request::Outcome<BSHJWTTokenClaims, Self::Error> {
		let mut file = match File::open("/easfiles/appliances/cookies/bsh_token.json") {
			Ok(file) => file,
			Err(_e) => return Outcome::Forward(()),
		};
		let mut contents = String::new();
		match file.read_to_string(&mut contents) {
			Ok(_) => (),
			Err(_e) => return Outcome::Forward(()),
		};
		let token_json: serde_json::Value = match serde_json::from_str(&contents) {
			Ok(token_json) => token_json,
			Err(_e) => return Outcome::Forward(()),
		};
		let token_str = match token_json["token"].as_str() {
			Some(token_str) => token_str,
			None => return Outcome::Forward(()),
		};
		match BSHJWTTokenClaims::decode(token_str).await {
			Ok(token_claims) => Outcome::Success(token_claims),
			Err(_e) => Outcome::Forward(()),
		}
	}
}
