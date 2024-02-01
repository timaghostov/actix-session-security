#![allow(unused_variables, dead_code)]

use actix_session_security::{
    logout_wrapper, secured_wrapper, LogoutWrapper, SecuredSession, SecuredWrapper,
};

use actix_web::{get, post, web, HttpResponse};

use crate::common::app::Application;
use crate::common::constants::SESSION_COOKIE_KEY;
use crate::common::error::ApiError;
use crate::common::models::Role;
use crate::common::models::SessionAggregate;

fn wrap_secured(roles: &'static [Role]) -> SecuredWrapper<Application, Role> {
    secured_wrapper(SESSION_COOKIE_KEY, roles)
}

fn wrap_logout() -> LogoutWrapper<Application, Role> {
    logout_wrapper(SESSION_COOKIE_KEY)
}

type Session = actix_session_security::Session<SessionAggregate>;

#[post("/login")]
async fn login(app: web::Data<Application>) -> Result<HttpResponse, ApiError> {
    let new_session = app.session_service.login().await?;

    Ok(HttpResponse::Ok()
        .cookie(new_session.logined_cookie())
        .finish())
}

#[get("/guest_handle")]
async fn guest_handle() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[get("/editor_handle", wrap = "wrap_secured(&[Role::Editor])")]
async fn editor_handle(
    _app: web::Data<Application>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok().finish())
}

#[get("/admin_handle", wrap = "wrap_secured(&[Role::Admin])")]
async fn admin_handle(session: Session) -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[get(
    "/editor_admin_handle",
    wrap = "wrap_secured(&[Role::Editor, Role::Admin])"
)]
async fn editor_admin_handle(
    _app: web::Data<Application>,
    session: Session,
) -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok().finish())
}

#[get("/logout", wrap = "wrap_logout()")]
async fn logout(app: web::Data<Application>, session: Session) -> Result<HttpResponse, ApiError> {
    let session_id = session
        .as_inner()
        .as_ref()
        .map(|s| s.session.session_id)
        .ok_or(ApiError::Unauthorized)?;
    app.session_service.logout(session_id).await?;

    Ok(HttpResponse::Ok()
        .cookie(SessionAggregate::guest_cookie())
        .finish())
}

pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login)
        .service(guest_handle)
        .service(editor_handle)
        .service(admin_handle)
        .service(editor_admin_handle)
        .service(logout);
}
