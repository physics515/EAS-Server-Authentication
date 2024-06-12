#![allow(dead_code)]
use std::fs::{self, File};
use std::path::Path;

use rocket::http::Status;
use rocket::log::private::info;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};
use serde::{Deserialize, Serialize};

use crate::tokens::WorkBookVersions;
use crate::tokens::WorkbookJWTTokenClaims;

///
/// # Workbook
/// Stores the workbook data.
///
/// ## Fields
/// token: The Workbook JSON Web Token (JWT) is use to store the API key for the excel Sales Workbook.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workbook {
	pub key: String,
	pub version: WorkBookVersions,
}

impl Workbook {
	///
	/// Creates a new Workbook.
	///
	/// # Errors
	/// todo
	pub fn new(version: &str) -> Result<Self, String> {
		let mut key = WorkbookJWTTokenClaims::new_key();
		let mut path = format!("/easfiles/workbook/{key:?}.json");

		while Path::new(&path).exists() {
			key = WorkbookJWTTokenClaims::new_key();
			path = format!("/easfiles/workbook/{key:?}.json");
		}

		let version: WorkBookVersions = match version.parse() {
			Ok(version) => version,
			Err(e) => return Err(format!("Could not parse workbook version: {e:?}")),
		};

		let workbook = Self { key, version };

		// save workbook to file
		match Path::new(&path).parent() {
			Some(parent) => {
				if !parent.exists() {
					match fs::create_dir_all(parent) {
						Ok(()) => (),
						Err(e) => return Err(format!("Faild to create parent directory: {e}")),
					};
				}
			}
			None => {
				info!("No parent directory found for {:?}", path);
			}
		}
		match File::create(&path) {
			Ok(_) => (),
			Err(e) => return Err(e.to_string()),
		};
		let json = match serde_json::to_string(&workbook) {
			Ok(json) => json,
			Err(e) => return Err(e.to_string()),
		};
		match fs::write(path, json) {
			Ok(()) => (),
			Err(e) => return Err(e.to_string()),
		};

		Ok(workbook)
	}

	///
	/// Opens an existing workbook.
	///
	/// # Errors
	/// todo
	#[allow(dead_code)]
	pub fn open(key: &str) -> Result<Self, String> {
		let path = format!("/easfiles/workbook/{key:?}.json");
		let Ok(file) = File::open(path) else {
			return Err(format!("Workbook with key {key} does not exist."));
		};

		let Ok(workbook) = serde_json::from_reader(file) else {
			return Err(format!("Faild to open workbook {key}."));
		};

		Ok(workbook)
	}
}

///
/// # Workbook - FromRequest
/// Gets the workbook from the request if the workbook JWT is valid then continue otherwise return forward to next ranked route.
///
#[rocket::async_trait]
impl<'r> FromRequest<'r> for Workbook {
	type Error = std::convert::Infallible;

	async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
		let cookie = request.cookies().get("eggersmann-workbook-jwt");

		if let Some(cookie) = cookie {
			let Ok(key) = WorkbookJWTTokenClaims::decode(cookie.value()).await else { return Outcome::Forward(Status::InternalServerError) };
			let workbook = Self { key: key.key, version: key.version };

			Outcome::Success(workbook)
		} else {
			info!("No User cookie found");
			Outcome::Forward(Status::BadRequest)
		}
	}
}
