use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error("SessionId not found")]
    SessionIdNotFound,
}
