#![deny(missing_docs)]
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;

use azure_identity::ImdsManagedIdentityCredential;
use azure_security_keyvault::KeyvaultClient;
use serde::{Deserialize, Serialize};

/// # Microsoft Azure Active Directory Athuentication Token
/// This token is used to authenticate with the Microsoft Graph API and other Microsoft services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MSAccessToken {
	/// Type of token
	pub token_type: String,
	/// Expiration duration
	pub expires_in: u64,
	/// Extention expiration duration
	pub ext_expires_in: u64,
	/// Token
	pub access_token: String,
}

impl MSAccessToken {
	/// # New MSAccessToken
	/// Creates a new MSAccessToken from the code returned by the Microsoft Azure Active Directory Authentication endpoint.
	pub async fn new(code: String) -> MSAccessToken {
		// login to Azure Key Vault
		let azure_credentials = ImdsManagedIdentityCredential::default();
		let client = match KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)) {
			Ok(client) => client,
			Err(e) => panic!("Faild to login to Azure Key Vault: {e:?}"),
		};

		// # Microsoft Authentication Client ID
		// The client id of the application registered in Azure Active Directory.
		let client_id = match client.secret_client().get("ms-auth-client-id").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get client id secret: {e:?}"),
		};

		// # Microsoft Authentication Redirect URI
		// The redirect uri to tell Azure AD where to return the user after they have authenticated.
		let redirect = match client.secret_client().get("ms-auth-redirect-uri").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get redirect uri secret: {e:?}"),
		};

		// # Microsoft Authenication Scope
		// The Azure AD authentication scope of the application.
		let scope = match client.secret_client().get("ms-auth-scope").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get scope secret: {e:?}"),
		};

		// # Microsoft Authentication Token Grant Type
		// The Azure AD authentication grant type of the application.
		let grant_type = match client.secret_client().get("ms-auth-token-grant-type").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get grant type secret: {e:?}"),
		};

		// # Microsoft Authentication Client Secret
		// The client secret of the application registered in Azure Active Directory.
		let client_secret = match client.secret_client().get("ms-auth-client-secret").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get client secret secret: {e:?}"),
		};

		// create parameter for use in the Microsoft Authentication endpoint
		let params = [("client_id", client_id.value), ("scope", scope.value), ("redirect_uri", redirect.value), ("grant_type", grant_type.value), ("client_secret", client_secret.value), ("code", code)];

		// load TSL certificate for use with reqwest client.
		let mut buf = Vec::new();
		let tls_cert_pem_path = match client.secret_client().get("tls-cert-pem-path").await {
			Ok(secret) => secret,
			Err(e) => panic!("Faild to get tls cert pem path secret: {e:?}"),
		};

		match File::open(tls_cert_pem_path.value) {
			Ok(mut file) => match file.read_to_end(&mut buf) {
				Ok(_) => (),
				Err(e) => panic!("Failed to read tls cert pem file: {e:?}"),
			},
			Err(_) => todo!(),
		}
		let cert = match reqwest::Certificate::from_pem(&buf) {
			Ok(cert) => cert,
			Err(e) => panic!("Failed to load tls cert pem file: {e:?}"),
		};
		let client = match reqwest::Client::builder().add_root_certificate(cert).build() {
			Ok(client) => client,
			Err(e) => panic!("Failed to build reqwest client: {e:?}"),
		};
		let response = match client.post("https://login.microsoftonline.com/common/oauth2/v2.0/token").form(&params).send().await {
			Ok(response) => response,
			Err(e) => panic!("Failed to send request to Microsoft Authentication endpoint: {e:?}"),
		};

		match response.json::<MSAccessToken>().await {
			Ok(token) => token,
			Err(_) => MSAccessToken { token_type: "".to_string(), expires_in: 0, ext_expires_in: 0, access_token: "".to_string() },
		}
	}
}
