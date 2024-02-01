use actix::prelude::*;
use async_trait::async_trait;
use uuid::Uuid;

use crate::common::error::AppError;
use crate::common::models::SessionAggregate;
use crate::common::session_factory::SessionFactoryAbstract;
use crate::common::strategy::Editor;

mod messages;
mod story;

use story::SessionStory;

#[async_trait]
pub trait SessionRepositoryAbstract: Sync + Send {
    async fn session_by_id(&self, session_id: &str) -> Result<SessionAggregate, AppError>;

    async fn login(&self) -> Result<SessionAggregate, AppError>;

    async fn logout(&self, session_id: Uuid) -> Result<(), AppError>;
}

#[derive(Debug)]
pub struct SessionRepository {
    addr: Addr<SessionStory>,
}

impl SessionRepository {
    pub fn new(session_factory: Box<dyn SessionFactoryAbstract>) -> Self {
        Self {
            addr: SessionStory::start(session_factory),
        }
    }
}

#[async_trait]
impl SessionRepositoryAbstract for SessionRepository {
    async fn session_by_id(&self, session_id: &str) -> Result<SessionAggregate, AppError> {
        let session_id = Uuid::parse_str(session_id).unwrap_or_default();
        self.addr
            .send(messages::SessionById::new(session_id))
            .await?
    }

    async fn login(&self) -> Result<SessionAggregate, AppError> {
        self.addr.send(messages::Login::<Editor>::new()).await?
    }

    async fn logout(&self, session_id: Uuid) -> Result<(), AppError> {
        self.addr.send(messages::Logout::new(session_id)).await?
    }
}
