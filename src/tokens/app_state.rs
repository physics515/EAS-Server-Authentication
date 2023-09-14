#![deny(missing_docs)]
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::user_types::AppState;

///
/// # Application State (AppState) JSON Web Token (JWT) Claims
/// This is the JSON Web Token (JWT) claims that will be included in the Application State (AppState) JSON Web Token (JWT).
/// The AppState JSON Web Token (JWT) is use to store any appliacation state information that needs to be passed via http requests.
///
/// For example, the AppState JSON Web Token (JWT) can be used to store the the current route that the user is on. So that after a user logs in, they can be redirected to the route they were on before they logged in.
/// The initial use for this token is for it to be passed as the state parameter to the Azure AD login url and Azure AD will pass it back to the application.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateTokenClaims {
	/// The current user route.
	pub uri: Option<String>,
	/// The expiration timestamp of the token.
	pub exp: u64,
}

impl AppStateTokenClaims {
	///
	/// Encodes the AppStateTokenClaims into a JWT string.
	///
	pub async fn encode(uri: String) -> Result<String, String> {
		let app_state_token_claim = AppStateTokenClaims { uri: Some(uri), exp: jsonwebtoken::get_current_timestamp() + 3600 };

		let creds = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(creds)) {
			Ok(client) => client.secret_client(),
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let user_token_secret = match client.get("user-token-secret").await {
			Ok(secret) => secret,
			Err(e) => return Err(format!("Faild to get user token secret: {e:?}")),
		};

		let token = encode(&Header::default(), &app_state_token_claim, &EncodingKey::from_secret(user_token_secret.value.as_bytes()));

		match token {
			Ok(token) => Ok(token),
			Err(e) => Err(format!("Failed to encode JWT token: {e:?}")),
		}
	}

	///
	/// Decodes the JWT string into an AppState.
	///
	pub async fn decode(token: &str) -> Result<AppState, String> {
		let creds = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(creds)) {
			Ok(client) => client.secret_client(),
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let user_token_secret = match client.get("user-token-secret").await {
			Ok(secret) => secret,
			Err(e) => return Err(format!("Faild to get user token secret: {e:?}")),
		};
		let key = user_token_secret.value;
		let key = DecodingKey::from_secret(key.as_bytes());
		let validation = Validation::default();
		let claims = decode::<AppStateTokenClaims>(token, &key, &validation);
		match claims {
			Ok(claims) => Ok(AppState { token: claims.claims }),
			Err(e) => Err(format!("Failed to decode JWT token: {e:?}")),
		}
	}
}
