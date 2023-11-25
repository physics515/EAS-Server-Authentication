use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use serde::{Deserialize, Serialize};

use crate::tokens::UserJWTTokenClaims;

///
/// # User
/// Stores the user data.
///
/// ## Fields
/// token: The JSON Web Token that stores session data on the users machine.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
	pub token: UserJWTTokenClaims,
}

///
/// # User - FromRequest
/// Gets the user from the request if the user JWT is valid then continue otherwise return forward to next ranked route.
///
#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
	type Error = std::convert::Infallible;

	async fn from_request(request: &'r Request<'_>) -> request::Outcome<User, Self::Error> {
		let cookie = request.cookies().get("eggersmann-user-jwt");

		match cookie {
			Some(cookie) => {
				let user = UserJWTTokenClaims::decode(cookie.value()).await;
				match user {
					Ok(user) => Outcome::Success(user),
					Err(_) => Outcome::Forward(Status::BadRequest),
				}
			}
			None => Outcome::Forward(Status::BadRequest),
		}
	}
}
