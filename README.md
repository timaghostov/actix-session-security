# actix-session-security


```
#[get("/admin_handle", wrap = "wrap_secured(&[Role::Admin])")]
async fn admin_handle(session: Session) -> HttpResponse {
    HttpResponse::Ok().finish()
}
```

see more examples