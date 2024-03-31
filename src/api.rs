use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    authentication::auth_middleware,
    handler::{
        get_user_handler, login_user_handler, logout_user_handler, main_handler,
        register_user_handler,
    },
    AppState,
};

pub fn create_api_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(main_handler))
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route(
            "/logout",
            get(logout_user_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/me",
            get(get_user_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .with_state(state)
}
