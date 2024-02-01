mod role;
mod session;
mod user;

pub use role::Role;
pub use session::Session;
pub use user::User;

#[derive(Debug, Clone)]
pub struct SessionAggregate {
    pub session: Session,
    pub user: User,
}

impl SessionAggregate {
    pub fn new(roles: Vec<Role>) -> Self {
        Self {
            session: Session::new(),
            user: User::new(roles),
        }
    }
}
