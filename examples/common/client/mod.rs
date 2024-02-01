use reqwest::cookie::Cookie;
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;
use reqwest::header::COOKIE;
use reqwest::Client;
use reqwest::Response;
use reqwest::Url;

use crate::common::constants::HOST;
use crate::common::constants::PORT;
use crate::common::constants::SESSION_COOKIE_KEY;

mod call_admin_handle;
mod call_editor_admin_handle;
mod call_editor_handle;
mod call_forbidden;
mod call_guest_handle;
mod call_login;
mod call_logout;
mod call_unauthorized;
mod error;

pub use call_admin_handle::call_admin_handle;
pub use call_editor_admin_handle::call_editor_admin_handle;
pub use call_editor_handle::call_editor_handle;
pub use call_forbidden::call_forbidden;
pub use call_guest_handle::call_guest_handle;
pub use call_login::call_login;
pub use call_logout::call_logout;
pub use call_unauthorized::call_unauthorized;

fn base_url() -> Url {
    Url::parse(&format!("http://{HOST}:{PORT}")).unwrap()
}

fn client() -> Client {
    Client::new()
}

fn find_cookie_session_id<'a>(response: &'a Response) -> Option<Cookie<'a>> {
    response
        .cookies()
        .find(|cookie| cookie.name() == SESSION_COOKIE_KEY)
}

fn build_header_session_cookie(session_id: &str) -> (HeaderName, HeaderValue) {
    let cookie_value = format!("{SESSION_COOKIE_KEY}={session_id}");
    (COOKIE, HeaderValue::from_str(&cookie_value).unwrap())
}
