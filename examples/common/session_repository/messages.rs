use std::marker::PhantomData;

use actix::prelude::*;
use uuid::Uuid;

use crate::common::error::AppError;
use crate::common::models::SessionAggregate;

#[derive(Debug, Message)]
#[rtype(result = "Result<SessionAggregate, AppError>")]
pub struct SessionById {
    pub session_id: Uuid,
}

impl SessionById {
    pub fn new(session_id: Uuid) -> Self {
        Self { session_id }
    }
}

#[derive(Debug, Message)]
#[rtype(result = "Result<SessionAggregate, AppError>")]
pub struct Login<Strategy> {
    role_strategy: PhantomData<Strategy>,
}

impl<Strategy> Login<Strategy> {
    pub fn new() -> Self {
        Self {
            role_strategy: PhantomData::<Strategy>,
        }
    }
}

#[derive(Debug, Message)]
#[rtype(result = "Result<(), AppError>")]
pub struct Logout {
    pub session_id: Uuid,
}

impl Logout {
    pub fn new(session_id: Uuid) -> Self {
        Self { session_id }
    }
}
