use std::{
    cell::{Ref, RefCell},
    rc::Rc,
};

use actix_web::{
    cookie::Cookie,
    dev::{Extensions, Payload, ServiceRequest},
    Error, FromRequest, HttpMessage, HttpRequest,
};

use futures::future;

use crate::traits::{SecuredSession, SessionRole};

// use secured_cookie_session::SecuredSession;
// use secured_cookie_session::SessionRole;

struct SessionInner<SessionType> {
    session: Option<SessionType>,
}

pub struct Session<SessionType>(Rc<RefCell<SessionInner<SessionType>>>);

impl<SessionType> Default for SessionInner<SessionType> {
    fn default() -> Self {
        Self { session: None }
    }
}

impl<RoleType, SessionType> Session<SessionType>
where
    RoleType: SessionRole,
    SessionType: SecuredSession<Role = RoleType> + 'static,
{
    pub fn set_session(req: &ServiceRequest, session_object: SessionType) {
        let session = Session::get_session(&mut req.extensions_mut());
        let mut inner = session.0.borrow_mut();
        inner.session = Some(session_object);
    }

    fn get_session(extensions: &mut Extensions) -> Self {
        if let Some(inner) = extensions.get::<Rc<RefCell<SessionInner<SessionType>>>>() {
            return Session(Rc::clone(inner));
        }
        let inner = Rc::new(RefCell::new(SessionInner::default()));
        extensions.insert(inner.clone());
        Session(inner)
    }

    pub fn is_authorized(&self) -> bool {
        self.0.borrow().session.is_some()
    }

    pub fn has_access(&self, assigned_roles: &[RoleType]) -> bool {
        match self.0.borrow().session.as_ref() {
            Some(session) => session.has_access(assigned_roles),
            None => false,
        }
    }

    pub fn cookie(&self) -> Cookie<'static> {
        match self.0.borrow().session.as_ref() {
            Some(session) => session.logined_cookie(),
            None => SessionType::guest_cookie(),
        }
    }

    pub fn as_inner(&self) -> Ref<'_, Option<SessionType>> {
        Ref::map(self.0.borrow(), |inner| &inner.session)
    }
}

impl<RoleType, SessionType> FromRequest for Session<SessionType>
where
    RoleType: SessionRole,
    SessionType: SecuredSession<Role = RoleType> + 'static,
{
    type Error = Error;
    type Future = future::Ready<Result<Session<SessionType>, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        future::ready(Ok(Session::get_session(&mut req.extensions_mut())))
    }
}
