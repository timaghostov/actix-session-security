use std::fmt::Display;

use actix_web::cookie::time::Duration;
use actix_web::cookie::Cookie;
use actix_web::cookie::SameSite;

use crate::common::constants::SESSION_COOKIE_KEY;

const EMPTY_SESSION_VALUE: &str = "";
const APP_DOMAIN: &str = ".domain.com";

pub fn create_cookie(session_id: impl Display, max_age: Duration) -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE_KEY, session_id.to_string())
        .secure(true)
        .http_only(true)
        .domain(APP_DOMAIN)
        .same_site(SameSite::Strict)
        .max_age(max_age)
        .path("/")
        .finish()
}

pub fn create_guest_cookie() -> Cookie<'static> {
    create_cookie(EMPTY_SESSION_VALUE, Duration::ZERO)
}
