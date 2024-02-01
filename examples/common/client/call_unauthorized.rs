use reqwest::StatusCode;
use reqwest::Url;

use crate::common::client::base_url;
use crate::common::client::build_header_session_cookie;
use crate::common::client::client;
use crate::common::client::error::ClientError;

fn url() -> Url {
    base_url().join("/editor_admin_handle").unwrap()
}

pub async fn call_unauthorized(some_session_id: &str) -> Result<(), ClientError> {
    let (header_name, header_value) = build_header_session_cookie(some_session_id);

    let response = client()
        .get(url())
        .header(header_name, header_value)
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    Ok(())
}
