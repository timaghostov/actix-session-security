use crate::common::session_factory::SessionFactoryAbstract;
use crate::common::session_repository::SessionRepository;
use crate::common::session_service::SessionService;

pub struct Application {
    pub session_service: SessionService,
}

impl Application {
    pub fn new(session_factory: Box<dyn SessionFactoryAbstract>) -> Self {
        let session_repository = Box::new(SessionRepository::new(session_factory));
        let session_service = SessionService::new(session_repository);
        Self { session_service }
    }
}
