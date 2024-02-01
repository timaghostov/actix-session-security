use std::time::Duration;

use reqwest::StatusCode;
use reqwest::Url;

use crate::common::client::base_url;
use crate::common::client::client;
use crate::common::client::error::ClientError;
use crate::common::client::find_cookie_session_id;
use crate::common::constants::SESSION_LIFETIME;

fn url() -> Url {
    base_url().join("/login").unwrap()
}

pub async fn call_login() -> Result<String, ClientError> {
    let response = client().post(url()).send().await?;

    assert_eq!(response.status(), StatusCode::OK);

    let cookie = find_cookie_session_id(&response).ok_or(ClientError::SessionIdNotFound)?;

    assert!(!cookie.value().is_empty());
    assert_eq!(
        cookie.max_age(),
        Some(Duration::from_secs(SESSION_LIFETIME as u64))
    );

    Ok(cookie.value().to_owned())
}
