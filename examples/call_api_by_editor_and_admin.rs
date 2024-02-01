#![allow(unused_imports)]

extern crate actix_session_security;

mod common;
mod impl_traits;
mod routes;

use common::session_factory::SessionFactory;
use common::strategy::EditorAdmin;

type ExampleSessionFactory = SessionFactory<EditorAdmin>;

#[actix_web::main]
async fn main() -> Result<(), std::io::Error> {
    let session_factory = Box::new(ExampleSessionFactory::new());

    let server = common::create_server::create_server(session_factory, routes::routes).await?;

    let server_handle = server.handle();
    actix_web::rt::spawn(server);

    common::client::call_guest_handle().await.unwrap();

    common::client::call_unauthorized("").await.unwrap();

    let session_id = common::client::call_login().await.unwrap();

    common::client::call_editor_handle(&session_id)
        .await
        .unwrap();

    common::client::call_admin_handle(&session_id)
        .await
        .unwrap();

    common::client::call_editor_admin_handle(&session_id)
        .await
        .unwrap();

    common::client::call_logout(&session_id).await.unwrap();

    common::client::call_unauthorized(&session_id)
        .await
        .unwrap();

    server_handle.stop(true).await;

    Ok(())
}
