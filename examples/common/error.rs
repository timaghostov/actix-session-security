use actix::prelude::*;
use actix_web::HttpResponse;
use actix_web::ResponseError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Session not found")]
    SessionNotFound,
    #[error(transparent)]
    Mailbox(#[from] MailboxError),
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    App(#[from] AppError),
    #[error("Session not found")]
    Unauthorized,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::App(AppError::SessionNotFound) => HttpResponse::NotFound(),
            Self::App(AppError::Mailbox(_)) => HttpResponse::InternalServerError(),
            Self::Unauthorized => HttpResponse::Unauthorized(),
        }
        .finish()
    }
}
