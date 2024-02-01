use reqwest::StatusCode;
use reqwest::Url;

use crate::common::client::base_url;
use crate::common::client::client;
use crate::common::client::error::ClientError;

fn url() -> Url {
    base_url().join("/guest_handle").unwrap()
}

pub async fn call_guest_handle() -> Result<(), ClientError> {
    let response = client().get(url()).send().await?;

    assert_eq!(response.status(), StatusCode::OK);

    Ok(())
}
