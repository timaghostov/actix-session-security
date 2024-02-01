use actix_web::{cookie::Cookie, dev::ServiceRequest, error::InternalError, http::StatusCode, web};

use crate::traits::{SecuredSession, SessionRole, SessionService};

pub fn session_id(
    req: &ServiceRequest,
    cookie_name: &'static str,
) -> Result<Cookie<'static>, InternalError<&'static str>> {
    req.cookie(cookie_name)
        .ok_or_else(|| InternalError::new("Unknown session cookie", StatusCode::UNAUTHORIZED))
}

pub fn application_context<AppContext>(
    req: &ServiceRequest,
) -> Result<web::Data<AppContext>, InternalError<&'static str>>
where
    AppContext: 'static,
{
    req.app_data::<web::Data<AppContext>>()
        .ok_or_else(|| {
            InternalError::new(
                "Unknown application context",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })
        .cloned()
}

pub async fn session<RoleType, SessionType, Service>(
    session_service: &Service,
    session_id: &str,
) -> Result<SessionType, InternalError<&'static str>>
where
    RoleType: SessionRole,
    SessionType: SecuredSession<Role = RoleType> + 'static,
    Service: SessionService<Role = RoleType, Session = SessionType> + 'static,
{
    session_service
        .session_by_id(session_id)
        .await
        .ok_or_else(|| InternalError::new("Session not found", StatusCode::UNAUTHORIZED))
}

pub fn forbidden_error() -> InternalError<&'static str> {
    InternalError::new("No grants", StatusCode::FORBIDDEN)
}
