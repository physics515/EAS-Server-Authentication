use serde::{Deserialize, Serialize};

use crate::tokens::AppStateTokenClaims;

///
/// # Application State
/// Keeps track of the application state.
///
/// token: Contains the token that is used to store any information that needs to be passed via http requests.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
	pub token: AppStateTokenClaims,
}
