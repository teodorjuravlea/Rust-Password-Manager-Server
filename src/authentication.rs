use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};

use axum_extra::extract::cookie::CookieJar;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::Serialize;

use crate::{database::get_user_by_id, model::TokenClaims, AppState};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

pub async fn auth_middleware(
    cookie_jar: CookieJar,
    State(data): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Get token from request
    let token = cookie_jar
        .get("token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value.split_at(7).1.to_string())
                    } else {
                        None
                    }
                })
        });

    // Check if token is present
    let token = token.ok_or_else(|| {
        let json_error = ErrorResponse {
            status: "error",
            message: "No token provided".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // Check if token is valid
    let claims = decode::<TokenClaims>(
        &token,
        &DecodingKey::from_secret(data.config.jwt_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| {
        let json_error = ErrorResponse {
            status: "error",
            message: "Invalid token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?
    .claims;

    // Get user id from token
    let user_id = uuid::Uuid::parse_str(&claims.user_id).map_err(|_| {
        let json_error = ErrorResponse {
            status: "error",
            message: "Invalid token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // Get user from database
    let user = get_user_by_id(user_id, &data.db).await.map_err(|e| {
        let json_error = ErrorResponse {
            status: "error",
            message: format!("Error fetching user from db: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    // Check if token refers to a valid user
    let user = user.ok_or_else(|| {
        let json_error = ErrorResponse {
            status: "error",
            message: "The token does not refer to a valid user".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(json_error))
    })?;

    // Add user to request
    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
