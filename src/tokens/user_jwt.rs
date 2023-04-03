#![warn(missing_docs)]
use crate::user_types::User;
use super::MSAccessToken;
use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

///
/// # User JSON Web Token (JWT) Claims
/// This is the JSON Web Token (JWT) claims that will be included in the User JSON Web Token (JWT).
/// The User JSON Web Token (JWT) is used identitiy information. This is stored on the user's machine via cookies.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserJWTTokenClaims {
        /// User ID
	pub id: String,
        /// Given name of user
	pub given_name: Option<String>,
        /// User last name
	pub surname: Option<String>,
        /// Display name of user
	pub display_name: Option<String>,
        /// User job title
	pub job_title: Option<String>,
        /// User first name
	pub user_principal_name: Option<String>,
        /// User's office location
	pub office_location: Option<String>,
        /// MS Access Token
	pub ms_token: MSAccessToken,
        /// Expiration timestamp
	pub exp: u64,
}

impl UserJWTTokenClaims {
	///
	/// Encodes the UserJWTTokenClaims into a JWT string.
	///
	pub async fn encode(ms_token: MSAccessToken) -> Result<String, String> {
		let client = reqwest::Client::new();
		let response = client.get("https://graph.microsoft.com/v1.0/me").bearer_auth(&ms_token.access_token).send().await;

		match response {
			Ok(response) => {
				let body: serde_json::Value = match response.json().await {
					Ok(body) => body,
					Err(e) => return Err(format!("Failed to get user info: {e:?}")),
				};

				let id = match body["id"].as_str() {
					Some(id) => id.to_string(),
					None => return Err("Failed to get user id".to_string()),
				};

				let given_name = body["givenName"].as_str().map(|given_name| given_name.to_string());

				let surname = body["surname"].as_str().map(|surname| surname.to_string());

				let display_name = body["displayName"].as_str().map(|display_name| display_name.to_string());

				let job_title = body["jobTitle"].as_str().map(|job_title| job_title.to_string());

				let jwt_token_claim = UserJWTTokenClaims {
					id,
					given_name,
					surname,
					display_name,
					job_title,
					user_principal_name: body["userPrincipalName"].as_str().map(|s| s.to_string()),
					office_location: body["officeLocation"].as_str().map(|s| s.to_string()),
					ms_token: ms_token.clone(),
					exp: jsonwebtoken::get_current_timestamp() + ms_token.expires_in,
				};

				println!("tonken expires in {}", ms_token.expires_in);

				let azure_credentials = ImdsManagedIdentityCredential::default();
				let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
					Ok(client) => client,
					Err(e) => return Err(format!("Failed to create key client: {e:?}")),
				};
				let user_token_secret = match client.secret_client().get("user-token-secret").await {
					Ok(user_token_secret) => user_token_secret,
					Err(e) => return Err(format!("Failed to get user token secret: {e:?}")),
				};
				let user_token_secret = user_token_secret.value;

				let token = encode(&Header::default(), &jwt_token_claim, &EncodingKey::from_secret(user_token_secret.as_bytes()));

				match token {
					Ok(token) => Ok(token),
					Err(e) => {
						println!("{e:?}");
						Err("Failed to encode JWT token".to_string())
					}
				}
			}
			Err(e) => {
				println!("{e:?}");
				Err("Failed to get user info".to_string())
			}
		}
	}

	///
	/// Decodes the JWT string into a User.
	///
	pub async fn decode(token: &str) -> Result<User, String> {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => return Err(format!("Failed to create key client: {e:?}")),
		};
		let user_token_secret = match client.secret_client().get("user-token-secret").await {
			Ok(user_token_secret) => user_token_secret,
			Err(e) => return Err(format!("Failed to get user token secret: {e:?}")),
		};
		let key = user_token_secret.value;
		let key = DecodingKey::from_secret(key.as_bytes());
		let validation = Validation::default();
		let claims = decode::<UserJWTTokenClaims>(token, &key, &validation);
		match claims {
			Ok(claims) => Ok(User { token: claims.claims }),
			Err(e) => {
				println!("{e:?}");
				Err("Failed to decode JWT token".to_string())
			}
		}
	}
}
