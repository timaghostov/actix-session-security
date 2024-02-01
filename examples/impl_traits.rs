use actix_web::cookie::Cookie;
use async_trait::async_trait;

use actix_session_security::SecuredSession;
use actix_session_security::SessionService;

use super::common::app::Application;
use super::common::create_cookie::create_cookie;
use super::common::create_cookie::create_guest_cookie;
use super::common::models::Role;
use super::common::models::SessionAggregate;

#[async_trait]
impl SessionService for Application {
    type Role = Role;

    type Session = SessionAggregate;

    async fn session_by_id(&self, session_id: &str) -> Option<Self::Session> {
        self.session_service.session_by_id(session_id).await.ok()
    }
}

impl SecuredSession for SessionAggregate {
    type Role = Role;

    fn roles(&self) -> &[Self::Role] {
        &self.user.roles
    }

    fn guest_cookie() -> Cookie<'static> {
        create_guest_cookie()
    }

    fn logined_cookie(&self) -> Cookie<'static> {
        create_cookie(self.session.session_id, self.session.lifetime)
    }
}
