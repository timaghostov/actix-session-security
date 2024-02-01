use uuid::Uuid;

use crate::common::error::AppError;
use crate::common::models::SessionAggregate;
use crate::common::session_repository::SessionRepositoryAbstract;

pub struct SessionService {
    session_repository: Box<dyn SessionRepositoryAbstract>,
}

impl SessionService {
    pub fn new(session_repository: Box<dyn SessionRepositoryAbstract>) -> Self {
        Self { session_repository }
    }

    pub async fn session_by_id(&self, session_id: &str) -> Result<SessionAggregate, AppError> {
        self.session_repository.session_by_id(session_id).await
    }

    pub async fn login(&self) -> Result<SessionAggregate, AppError> {
        self.session_repository.login().await
    }

    pub async fn logout(&self, session_id: Uuid) -> Result<(), AppError> {
        self.session_repository.logout(session_id).await
    }
}
