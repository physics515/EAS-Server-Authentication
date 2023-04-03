pub use api_key::ApiKey;
pub use user_types::*;
pub use tokens::*;

use std::sync::Arc;
use azure_security_keyvault::KeyvaultClient;
use azure_identity::ImdsManagedIdentityCredential;
use std::collections::HashMap;
use rocket::uri;

mod api_key;
mod user_types;
mod tokens;

pub async fn microsoft_365_auth_url() -> String {
        let mut params = HashMap::new();
	let azure_credentials = ImdsManagedIdentityCredential::default();
	let client = KeyvaultClient::new("https://eggappserverkeyvault.vault.azure.net", Arc::new(azure_credentials)).unwrap();

	let ms_auth_client_id = client.secret_client().get("ms-auth-client-id").await.unwrap();
	let ms_auth_response_type = client.secret_client().get("ms-auth-response-type").await.unwrap();
	let ms_auth_redirect_uri = client.secret_client().get("ms-auth-redirect-uri").await.unwrap();
	let ms_auth_response_mode = client.secret_client().get("ms-auth-response-mode").await.unwrap();
	let ms_auth_scope = client.secret_client().get("ms-auth-scope").await.unwrap();
	let ms_auth_url = client.secret_client().get("ms-auth-url").await.unwrap();

	let state = AppStateTokenClaims::encode(uri!("/").to_string()).await.unwrap();

	params.insert("client_id", ms_auth_client_id.value);
	params.insert("response_type", ms_auth_response_type.value);
	params.insert("redirect_uri", ms_auth_redirect_uri.value);
	params.insert("response_mode", ms_auth_response_mode.value);
	params.insert("scope", ms_auth_scope.value);
	params.insert("state", state);

        url::form_urlencoded::Serializer::new(ms_auth_url.value.to_owned()).extend_pairs(params).finish()
}

pub async fn microsoft_365_code_to_user_token(code: &str) -> Result<String, String> {
        let ms_token = MSAccessToken::new(code.to_string()).await;
        UserJWTTokenClaims::encode(ms_token).await
}