use std::sync::Arc;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};

use crate::{
    authentication::auth_middleware,
    handler::{
        add_encrypted_data_entry_handler, delete_encrypted_data_entry_handler,
        get_all_encrypted_data_entries_handler, get_user_handler, login_user_handler,
        logout_user_handler, main_handler, register_user_handler,
        update_encrypted_data_entry_handler,
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
        .route(
            "/add_encrypted_data_entry",
            post(add_encrypted_data_entry_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/update_encrypted_data_entry",
            post(update_encrypted_data_entry_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/delete_encrypted_data_entry",
            post(delete_encrypted_data_entry_handler).route_layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/get_all_encrypted_data_entries",
            get(get_all_encrypted_data_entries_handler).route_layer(
                middleware::from_fn_with_state(state.clone(), auth_middleware),
            ),
        )
        .with_state(state)
}
