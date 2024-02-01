use std::marker::PhantomData;

use crate::common::models::Role;
use crate::common::models::SessionAggregate;
use crate::common::strategy::Admin;
use crate::common::strategy::Editor;
use crate::common::strategy::EditorAdmin;

pub trait SessionFactoryAbstract {
    fn create_session(&self) -> SessionAggregate;
}

#[derive(Debug)]
pub struct SessionFactory<T>(pub PhantomData<T>);

impl<T> SessionFactory<T> {
    pub fn new() -> Self {
        Self(PhantomData::<T>)
    }
}

impl SessionFactoryAbstract for SessionFactory<Editor> {
    fn create_session(&self) -> SessionAggregate {
        SessionAggregate::new(vec![Role::Editor])
    }
}

impl SessionFactoryAbstract for SessionFactory<Admin> {
    fn create_session(&self) -> SessionAggregate {
        SessionAggregate::new(vec![Role::Admin])
    }
}

impl SessionFactoryAbstract for SessionFactory<EditorAdmin> {
    fn create_session(&self) -> SessionAggregate {
        SessionAggregate::new(vec![Role::Editor, Role::Admin])
    }
}
