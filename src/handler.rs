use axum::{
    extract::State,
    http::{
        header::{self},
        Response, StatusCode,
    },
    response::IntoResponse,
    Extension, Json,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::sync::Arc;

use crate::{
    database::{
        add_encrypted_data_entry, check_user_exists_by_email, create_user,
        delete_encrypted_data_entry, get_all_encrypted_data_entries_by_user_id, get_user_by_email,
        update_encrypted_data_entry,
    },
    model::{
        AddEncryptedDataEntryRequest, DeleteEncryptedDataEntryRequest, EncryptedDataEntryResponse,
        FilteredUser, GetAllEncryptedDataEntriesResponse, LoginRequest, RegisterRequest,
        TokenClaims, UpdateEncryptedDataEntryRequest, User, UserResponse,
    },
    utils::{self, is_password_valid},
    AppState,
};

fn filter_user(user: User) -> FilteredUser {
    FilteredUser {
        email: user.email.to_owned(),
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}

pub async fn main_handler() -> impl IntoResponse {
    const MESSAGE: &str = "Rust Password Manager Server";

    let json_response = serde_json::json!({ "message": MESSAGE });

    Json(json_response)
}

pub async fn register_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    println!("Registering user: {:?}", body);

    // Check if user already exists
    let user_exists: Option<bool> = check_user_exists_by_email(&body.email, &data.db)
        .await
        .map_err(|e| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": format!("Error checking if user exists: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    if let Some(exists) = user_exists {
        if exists {
            let json_error = serde_json::json!({
                "status": "error",
                "message": "User already exists",
            });

            println!("User already exists: {:?}", json_error);

            return Err((StatusCode::CONFLICT, Json(json_error)));
        }
    }

    // Hash password
    let password_hash = utils::generate_password_hash(&body.password)
        .await
        .map_err(|e| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": format!("Error hashing password: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    // Create user
    let user = create_user(&body.email, &password_hash, &data.db)
        .await
        .map_err(|e| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": format!("Error creating user in database: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    // Return user response
    let user_response = UserResponse {
        status: "success".to_owned(),
        data: filter_user(user),
    };

    println!("User created: {:?}", user_response);

    Ok(Json(user_response))
}

pub async fn login_user_handler(
    State(data): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Check if user exists
    let user = get_user_by_email(&body.email, &data.db)
        .await
        .map_err(|e| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": format!("Error fetching user from database: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?
        .ok_or_else(|| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": "Invalid email or password",
            });
            (StatusCode::BAD_REQUEST, Json(json_error))
        })?;

    // Check if password is correct
    if !is_password_valid(&body.password, &user.password_hash) {
        let json_error = serde_json::json!({
            "status": "error",
            "message": "Invalid email or password",
        });
        return Err((StatusCode::BAD_REQUEST, Json(json_error)));
    }

    // Create JWT
    let now = chrono::Utc::now();
    let claims = TokenClaims {
        user_id: user.id.to_string(),
        iat: now.timestamp() as usize,
        exp: (now + chrono::Duration::try_hours(1).unwrap()).timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(data.config.jwt_secret.as_ref()),
    )
    .unwrap();

    let cookie = Cookie::build(("token", token.to_owned()))
        .path("/")
        .max_age(time::Duration::hours(1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response =
        Response::new(json!({"status": "success", "data": {"token": token}}).to_string());

    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    println!("User logged in: {:?}", response);

    Ok(response)
}

pub async fn logout_user_handler(
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let cookie = Cookie::build(("token", ""))
        .path("/")
        .max_age(time::Duration::hours(-1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let mut response = Response::new(json!({"status": "success"}).to_string());

    response
        .headers_mut()
        .insert(header::SET_COOKIE, cookie.to_string().parse().unwrap());

    println!("User logged out: {:?}", response);

    Ok(response)
}

pub async fn get_user_handler(
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let user_response = UserResponse {
        status: "success".to_owned(),
        data: filter_user(user),
    };

    println!("User retrieved: {:?}", user_response);

    Ok(Json(user_response))
}

pub async fn add_encrypted_data_entry_handler(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Json(body): Json<AddEncryptedDataEntryRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let encrypted_data_entry = add_encrypted_data_entry(
        user.id,
        &body.name,
        &body.content,
        &body.nonce,
        &body.content_type,
        &data.db,
    )
    .await
    .map_err(|e| {
        let json_error = serde_json::json!({
            "status": "error",
            "message": format!("Error adding encrypted data entry: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let encrypted_data_entry_response = EncryptedDataEntryResponse {
        status: "success".to_owned(),
        data: encrypted_data_entry,
    };

    println!(
        "Added encrypted data entry: {:?}",
        encrypted_data_entry_response
    );

    Ok(Json(encrypted_data_entry_response))
}

pub async fn update_encrypted_data_entry_handler(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Json(body): Json<UpdateEncryptedDataEntryRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let encrypted_data_entry = update_encrypted_data_entry(
        user.id,
        &body.content_type,
        &body.old_name,
        &body.new_name,
        &body.new_content,
        &body.new_nonce,
        &data.db,
    )
    .await
    .map_err(|e| {
        let json_error = serde_json::json!({
            "status": "error",
            "message": format!("Error updating encrypted data entry: {}", e),
        });
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
    })?;

    let encrypted_data_entry_response = EncryptedDataEntryResponse {
        status: "success".to_owned(),
        data: encrypted_data_entry,
    };

    println!(
        "Updated encrypted data entry: {:?}",
        encrypted_data_entry_response
    );

    Ok(Json(encrypted_data_entry_response))
}

pub async fn delete_encrypted_data_entry_handler(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Json(body): Json<DeleteEncryptedDataEntryRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let encrypted_data_entry =
        delete_encrypted_data_entry(user.id, &body.name, &body.content_type, &data.db)
            .await
            .map_err(|e| {
                let json_error = serde_json::json!({
                    "status": "error",
                    "message": format!("Error deleting encrypted data entry: {}", e),
                });
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
            })?;

    let json_response = serde_json::json!({
        "status": "success",
    });

    println!("Encrypted data entry deleted: {:?}", encrypted_data_entry);

    Ok(Json(json_response))
}

pub async fn get_all_encrypted_data_entries_handler(
    State(data): State<Arc<AppState>>,
    Extension(user): Extension<User>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let encrypted_data_entries = get_all_encrypted_data_entries_by_user_id(user.id, &data.db)
        .await
        .map_err(|e| {
            let json_error = serde_json::json!({
                "status": "error",
                "message": format!("Error fetching encrypted data entries: {}", e),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json_error))
        })?;

    let get_all_encrypted_data_entries_response = GetAllEncryptedDataEntriesResponse {
        status: "success".to_owned(),
        data: encrypted_data_entries,
    };

    println!(
        "Fetched all encrypted data entries: {:?}",
        get_all_encrypted_data_entries_response
    );

    Ok(Json(get_all_encrypted_data_entries_response))
}
