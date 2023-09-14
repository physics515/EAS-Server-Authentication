#![allow(dead_code)]
use std::fmt::Display;
use std::str;
use std::str::FromStr;
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::random;
use rocket::serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

///
/// # Workbook JSON Web Token (JWT) Claims
/// This is the JSON Web Token (JWT) claims that will be included in the Workbook JSON Web Token (JWT).
/// The Workbook JSON Web Token (JWT) is use to store the API key for the excel Sales Workbook.
///
/// Key: A unique key that is used as a unique identifier for the workbook.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkbookJWTTokenClaims {
	/// The key for the workbook.
	pub key: String,
	/// The version of the workbook.
	pub version: WorkBookVersions,
	/// The expiration time of the token.
	pub exp: u64,
}

impl WorkbookJWTTokenClaims {
	///
	/// Encodes the WorkbookJWTTokenClaims into a JWT string.
	///
	pub async fn encode(key: String, version: WorkBookVersions) -> Result<String, String> {
		let jwt_token_claim = WorkbookJWTTokenClaims { key, version, exp: jsonwebtoken::get_current_timestamp() + 3124135674 };
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let workbook_token_secret = match client.secret_client().get("workbook-token-secret").await {
			Ok(secret) => secret,
			Err(e) => return Err(format!("Faild to get workbook token secret: {e:?}")),
		};
		let workbook_token_secret = workbook_token_secret.value;

		let token = encode(&Header::default(), &jwt_token_claim, &EncodingKey::from_secret(workbook_token_secret.as_bytes()));

		match token {
			Ok(token) => Ok(token),
			Err(e) => Err(format!("Failed to encode JWT token: {e:?}")),
		}
	}

	///
	/// Decodes the JWT string into a Workbook.
	///
	pub async fn decode(token: &str) -> Result<WorkbookJWTTokenClaims, String> {
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => return Err(format!("Faild to login to Azure Key Vault: {e:?}")),
		};
		let workbook_token_secret = match client.secret_client().get("workbook-token-secret").await {
			Ok(secret) => secret,
			Err(e) => return Err(format!("Faild to get workbook token secret: {e:?}")),
		};
		let key = workbook_token_secret.value;
		let key = DecodingKey::from_secret(key.as_bytes());
		let validation = Validation::default();
		let claims = decode::<WorkbookJWTTokenClaims>(token, &key, &validation);
		match claims {
			Ok(claims) => Ok(claims.claims),
			Err(e) => Err(format!("Failed to decode JWT token: {e:?}")),
		}
	}

	///
	/// Generates a random key for the Workbook JSON Web Token (JWT).
	/// todo: this should check for uniqueness.
	///
	pub async fn new_key() -> String {
		let salt = random::<u128>();
		let date = Utc::now();
		let date_string = date.to_rfc3339();
		let date_string = date_string + &salt.to_string();
		let mut hasher = Sha256::new();
		hasher.update(date_string.as_bytes());
		format!("{:X}", hasher.finalize())
	}
}

///
/// # Workbook Versions
/// The version of the workbook.
/// This is used to determine which version of the workbook to use.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WorkBookVersions {
	/// Version 35.9.4 of the workbook.
	V35_9_4,
}

impl FromStr for WorkBookVersions {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_lowercase().as_str() {
			"v35.9.4" => Ok(WorkBookVersions::V35_9_4),
			_ => Err(()),
		}
	}
}

impl Display for WorkBookVersions {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			WorkBookVersions::V35_9_4 => write!(f, "v35.9.4"),
		}
	}
}
