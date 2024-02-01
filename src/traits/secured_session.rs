use actix_web::cookie::Cookie;

use crate::traits::secured_role::SessionRole;

pub trait SecuredSession
where
    Self: Sized,
{
    type Role: SessionRole;

    fn roles(&self) -> &[Self::Role];

    fn has_access(&self, assigned_roles: &[Self::Role]) -> bool {
        Self::is_roles_matching(self.roles(), assigned_roles)
    }

    fn is_roles_matching(current_roles: &[Self::Role], assigned_roles: &[Self::Role]) -> bool {
        current_roles
            .iter()
            .any(|role| assigned_roles.contains(role))
    }

    fn guest_cookie() -> Cookie<'static>;

    fn logined_cookie(&self) -> Cookie<'static>;
}
