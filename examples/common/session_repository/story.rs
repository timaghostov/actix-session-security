use std::collections::HashMap;

use actix::prelude::*;
use uuid::Uuid;

use crate::common::error::AppError;
use crate::common::models::SessionAggregate;
use crate::common::session_factory::SessionFactoryAbstract;
use crate::common::session_repository::messages::Login;
use crate::common::session_repository::messages::Logout;
use crate::common::session_repository::messages::SessionById;
use crate::common::strategy::Editor;

pub struct SessionStory {
    map: HashMap<Uuid, SessionAggregate>,
    session_factory: Box<dyn SessionFactoryAbstract>,
}

impl Actor for SessionStory {
    type Context = Context<Self>;
}

impl SessionStory {
    pub fn start(session_factory: Box<dyn SessionFactoryAbstract>) -> Addr<Self> {
        let actor = Self {
            map: HashMap::new(),
            session_factory,
        };
        actor.start()
    }
}

impl Handler<SessionById> for SessionStory {
    type Result = Result<SessionAggregate, AppError>;

    fn handle(
        &mut self,
        SessionById { session_id }: SessionById,
        _: &mut Context<Self>,
    ) -> Self::Result {
        let session = self
            .map
            .get(&session_id)
            .cloned()
            .ok_or(AppError::SessionNotFound)?;

        Ok(session)
    }
}

impl Handler<Login<Editor>> for SessionStory {
    type Result = Result<SessionAggregate, AppError>;

    fn handle(&mut self, _: Login<Editor>, _: &mut Context<Self>) -> Self::Result {
        let new_session = self.session_factory.create_session();

        let session_id = new_session.session.session_id;

        self.map.insert(session_id, new_session.clone());

        Ok(new_session)
    }
}

impl Handler<Logout> for SessionStory {
    type Result = Result<(), AppError>;

    fn handle(&mut self, Logout { session_id }: Logout, _: &mut Context<Self>) -> Self::Result {
        self.map.remove(&session_id);

        Ok(())
    }
}
