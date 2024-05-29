use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenClaims {
    pub user_id: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedDataEntry {
    pub user_id: uuid::Uuid,
    pub name: String,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub content_type: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

// Request structures
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct AddEncryptedDataEntryRequest {
    pub name: String,
    pub content: Vec<u8>,
    pub nonce: Vec<u8>,
    pub content_type: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateEncryptedDataEntryRequest {
    pub content_type: String,
    pub old_name: String,
    pub new_name: String,
    pub new_content: Vec<u8>,
    pub new_nonce: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteEncryptedDataEntryRequest {
    pub name: String,
    pub content_type: String,
}

// Response structures
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct FilteredUser {
    pub email: String,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub status: String,
    pub data: FilteredUser,
}

#[derive(Debug, Serialize)]
pub struct EncryptedDataEntryResponse {
    pub status: String,
    pub data: EncryptedDataEntry,
}

#[derive(Debug, Serialize)]
pub struct GetAllEncryptedDataEntriesResponse {
    pub status: String,
    pub data: Vec<EncryptedDataEntry>,
}
