use std::marker::PhantomData;
use std::rc::Rc;

use actix_web::{
    cookie::Cookie,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::{Error, InternalError},
    http::StatusCode,
    web,
};
use futures::future;

use crate::{
    traits::{SecuredSession, SessionRole, SessionService},
    wrappers::{session::Session, utils},
};

pub fn secured_wrapper<AppContext, RoleType>(
    session_cookie_key: &'static str,
    roles: &'static [RoleType],
) -> SecuredWrapper<AppContext, RoleType> {
    SecuredWrapper::new(session_cookie_key, roles)
}

pub struct SecuredWrapper<AppContext, RoleType: 'static> {
    session_cookie_name: &'static str,
    roles: &'static [RoleType],
    application_context: PhantomData<AppContext>,
}

impl<AppContext, RoleType> SecuredWrapper<AppContext, RoleType> {
    pub fn new(session_cookie_name: &'static str, roles: &'static [RoleType]) -> Self {
        Self {
            session_cookie_name,
            roles,
            application_context: PhantomData::<AppContext>,
        }
    }
}

impl<ActixService, B, RoleType, SessionType, AppContext> Transform<ActixService, ServiceRequest>
    for SecuredWrapper<AppContext, RoleType>
where
    ActixService: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    ActixService::Future: 'static,
    B: 'static,
    RoleType: SessionRole,
    SessionType: SecuredSession<Role = RoleType> + 'static,
    AppContext: SessionService<Role = RoleType, Session = SessionType> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SecuredWrapperMiddleware<ActixService, AppContext, RoleType>;
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: ActixService) -> Self::Future {
        future::ok(SecuredWrapperMiddleware {
            service: Rc::new(service),
            session_cookie_name: self.session_cookie_name,
            roles: self.roles,
            application_context: PhantomData::<AppContext>,
        })
    }
}

pub struct SecuredWrapperMiddleware<ActixService, AppContext, RoleType: 'static> {
    service: Rc<ActixService>,
    session_cookie_name: &'static str,
    roles: &'static [RoleType],
    application_context: PhantomData<AppContext>,
}

impl<ActixService, B, RoleType, SessionType, AppContext> Service<ServiceRequest>
    for SecuredWrapperMiddleware<ActixService, AppContext, RoleType>
where
    ActixService: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    ActixService::Future: 'static,
    B: 'static,
    RoleType: SessionRole,
    SessionType: SecuredSession<Role = RoleType> + 'static,
    AppContext: SessionService<Role = RoleType, Session = SessionType> + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let cookie_name = self.session_cookie_name;
        let roles = self.roles;

        Box::pin(async move {
            let session_cookie = utils::session_id(&req, cookie_name)?;
            let session_id = session_cookie.value();

            let application: web::Data<AppContext> = utils::application_context(&req)?;

            let session = utils::session(application.as_ref(), session_id).await?;

            if session.has_access(roles) {
                let cookie = &session.logined_cookie();
                Session::set_session(&req, session);

                let mut response = service.call(req).await?;
                response.response_mut().add_cookie(cookie)?;
                Ok(response)
            } else {
                Err(utils::forbidden_error().into())
            }
        })
    }
}
