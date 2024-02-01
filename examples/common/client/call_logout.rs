use std::time::Duration;

use reqwest::StatusCode;
use reqwest::Url;

use crate::common::client::base_url;
use crate::common::client::build_header_session_cookie;
use crate::common::client::client;
use crate::common::client::error::ClientError;
use crate::common::client::find_cookie_session_id;

fn url() -> Url {
    base_url().join("/logout").unwrap()
}

pub async fn call_logout(session_id: &str) -> Result<(), ClientError> {
    let (header_name, header_value) = build_header_session_cookie(session_id);

    let response = client()
        .get(url())
        .header(header_name, header_value)
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);

    let cookie = find_cookie_session_id(&response).ok_or(ClientError::SessionIdNotFound)?;

    assert!(cookie.value().is_empty());
    assert_eq!(cookie.max_age(), Some(Duration::ZERO));

    Ok(())
}
