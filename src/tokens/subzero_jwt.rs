#![deny(missing_docs)]
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use playwright::api::Cookie as PlaywrightCookie;
use serde::{Deserialize, Serialize};

///
/// # Subzero JSON Web Token (JWT) Claims
/// This is the JSON Web Token (JWT) claims that will be included in the SubZero JSON Web Token (JWT).
/// The SubZero JSON Web Token (JWT) is use to store cookies that are used by Playwright to authenticate to the SubZero website.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubZeroJWTTokenClaims {
	/// The expiration time of the token.
	pub exp: u64,
	/// The cookies that are used by Playwright to authenticate to the SubZero website.
	pub subzero_cookies: Vec<PlaywrightCookie>,
}

impl SubZeroJWTTokenClaims {
	///
	/// Encodes the SubZeroJWTTokenClaims into a JWT string.
	///
	pub async fn encode(subzero_cookies: Vec<PlaywrightCookie>) -> Result<String, String> {
		let jwt_token_claim = SubZeroJWTTokenClaims { exp: jsonwebtoken::get_current_timestamp() + 1500, subzero_cookies };

		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => panic!("Faild to login to Azure Key Vault: {e:?}"),
		};
		let user_token_secret = match client.secret_client().get("user-token-secret").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get user token secret: {e:?}"),
		};
		let user_token_secret = user_token_secret.value;

		let token = encode(&Header::default(), &jwt_token_claim, &EncodingKey::from_secret(user_token_secret.as_bytes()));

		match token {
			Ok(token) => Ok(token),
			Err(e) => Err(format!("Failed to encode JWT token: {e:?}")),
		}
	}

	///
	/// Decodes the JWT string into a SubZeroJWTTokenClaims.
	///
	pub async fn decode(token: &str) -> Result<SubZeroJWTTokenClaims, String> {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => panic!("Faild to login to Azure Key Vault: {e:?}"),
		};
		let user_token_secret = match client.secret_client().get("user-token-secret").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get user token secret: {e:?}"),
		};
		let key = user_token_secret.value;
		let key = DecodingKey::from_secret(key.as_bytes());
		let validation = Validation::default();
		let claims = decode::<SubZeroJWTTokenClaims>(token, &key, &validation);
		match claims {
			Ok(claims) => Ok(SubZeroJWTTokenClaims { exp: claims.claims.exp, subzero_cookies: claims.claims.subzero_cookies }),
			Err(e) => Err(format!("Failed to decode JWT token: {e:?}")),
		}
	}
}
