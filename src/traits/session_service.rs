use async_trait::async_trait;

use crate::traits::{secured_role::SessionRole, secured_session::SecuredSession};

#[async_trait]
pub trait SessionService {
    type Role: SessionRole;
    type Session: SecuredSession<Role = Self::Role>;

    async fn session_by_id(&self, session_id: &str) -> Option<Self::Session>;
}
