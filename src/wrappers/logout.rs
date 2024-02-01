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

pub fn logout_wrapper<AppContext, RoleType>(
    session_cookie_key: &'static str,
) -> LogoutWrapper<AppContext, RoleType> {
    LogoutWrapper::new(session_cookie_key)
}

pub struct LogoutWrapper<AppContext, RoleType> {
    session_cookie_name: &'static str,
    application_context: PhantomData<AppContext>,
    role_type: PhantomData<RoleType>,
}

impl<AppContext, RoleType> LogoutWrapper<AppContext, RoleType> {
    pub fn new(session_cookie_name: &'static str) -> Self {
        Self {
            session_cookie_name,
            application_context: PhantomData::<AppContext>,
            role_type: PhantomData::<RoleType>,
        }
    }
}

impl<ActixService, B, RoleType, SessionType, AppContext> Transform<ActixService, ServiceRequest>
    for LogoutWrapper<AppContext, RoleType>
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
    type Transform = LogoutWrapperMiddleware<ActixService, AppContext, RoleType>;
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: ActixService) -> Self::Future {
        future::ok(LogoutWrapperMiddleware {
            service: Rc::new(service),
            session_cookie_name: self.session_cookie_name,
            application_context: PhantomData::<AppContext>,
            role_type: PhantomData::<RoleType>,
        })
    }
}

pub struct LogoutWrapperMiddleware<ActixService, AppContext, RoleType> {
    service: Rc<ActixService>,
    session_cookie_name: &'static str,
    application_context: PhantomData<AppContext>,
    role_type: PhantomData<RoleType>,
}

impl<ActixService, B, RoleType, SessionType, AppContext> Service<ServiceRequest>
    for LogoutWrapperMiddleware<ActixService, AppContext, RoleType>
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

        Box::pin(async move {
            let session_cookie = utils::session_id(&req, cookie_name)?;
            let session_id = session_cookie.value();

            let application: web::Data<AppContext> = utils::application_context(&req)?;

            let session = utils::session(application.as_ref(), session_id).await?;

            Session::set_session(&req, session);

            service.call(req).await
        })
    }
}
