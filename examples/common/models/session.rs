use actix_web::cookie::time::Duration;

use uuid::Uuid;

use crate::common::constants::SESSION_LIFETIME;

#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: Uuid,
    pub lifetime: Duration,
}

impl Session {
    pub fn new() -> Self {
        Self {
            session_id: Uuid::new_v4(),
            lifetime: Duration::seconds(SESSION_LIFETIME),
        }
    }
}
