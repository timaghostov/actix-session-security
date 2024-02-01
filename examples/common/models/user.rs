use uuid::Uuid;

use crate::common::models::Role;

#[derive(Debug, Clone)]
pub struct User {
    pub user_id: Uuid,
    pub roles: Vec<Role>,
}

impl User {
    pub fn new(roles: Vec<Role>) -> Self {
        Self {
            user_id: Uuid::new_v4(),
            roles,
        }
    }
}
