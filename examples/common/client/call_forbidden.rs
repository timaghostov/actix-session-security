use reqwest::StatusCode;

use crate::common::client::base_url;
use crate::common::client::build_header_session_cookie;
use crate::common::client::client;
use crate::common::client::error::ClientError;

pub async fn call_forbidden(url: &str, session_id: &str) -> Result<(), ClientError> {
    let url = base_url().join(url).unwrap();

    let (header_name, header_value) = build_header_session_cookie(session_id);

    let response = client()
        .get(url)
        .header(header_name, header_value)
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}
