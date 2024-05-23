use crate::model::{EncryptedDataEntry, User};

pub async fn get_user_by_id(
    user_id: uuid::Uuid,
    db: &sqlx::PgPool,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE id = $1", user_id)
        .fetch_optional(db)
        .await
}

pub async fn get_user_by_email(
    email: &str,
    db: &sqlx::PgPool,
) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE email = $1", email)
        .fetch_optional(db)
        .await
}

pub async fn check_user_exists_by_email(
    email: &str,
    db: &sqlx::PgPool,
) -> Result<Option<bool>, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(email.to_ascii_lowercase())
        .fetch_one(db)
        .await
}

pub async fn create_user(
    email: &str,
    password_hash: &str,
    db: &sqlx::PgPool,
) -> Result<User, sqlx::Error> {
    sqlx::query_as!(
        User,
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *",
        email.to_ascii_lowercase(),
        password_hash,
    )
    .fetch_one(db)
    .await
}

/*pub async fn get_all_encrypted_data_entries_by_user_id(
    user_id: uuid::Uuid,
    db: &sqlx::PgPool,
) -> Result<Vec<EncryptedDataEntry>, sqlx::Error> {
    sqlx::query_as!(
        EncryptedDataEntry,
        "SELECT * FROM encrypted_data_entries WHERE user_id = $1",
        user_id
    )
    .fetch_all(db)
    .await
}*/

pub async fn add_encrypted_data_entry(
    user_id: uuid::Uuid,
    name: &str,
    content: &str,
    content_type: &str,
    db: &sqlx::PgPool,
) -> Result<EncryptedDataEntry, sqlx::Error> {
    sqlx::query_as!(
        EncryptedDataEntry,
        "INSERT INTO encrypted_data_entries (user_id, name, content, content_type) VALUES ($1, $2, $3, $4) RETURNING *",
        user_id,
        name,
        content,
        content_type,
    )
    .fetch_one(db)
    .await
}

pub async fn update_encrypted_data_entry(
    user_id: uuid::Uuid,
    content_type: &str,
    old_name: &str,
    new_name: &str,
    new_content: &str,
    db: &sqlx::PgPool,
) -> Result<EncryptedDataEntry, sqlx::Error> {
    sqlx::query_as!(
        EncryptedDataEntry,
        "UPDATE encrypted_data_entries SET name = $1, content = $2, updated_at = NOW() WHERE user_id = $3 AND name = $4 AND content_type = $5 RETURNING *",
        new_name,
        new_content,
        user_id,
        old_name,
        content_type,
    )
    .fetch_one(db)
    .await
}

pub async fn delete_encrypted_data_entry(
    user_id: uuid::Uuid,
    name: &str,
    content_type: &str,
    db: &sqlx::PgPool,
) -> Result<EncryptedDataEntry, sqlx::Error> {
    sqlx::query_as!(
        EncryptedDataEntry,
        "DELETE FROM encrypted_data_entries WHERE user_id = $1 AND name = $2 AND content_type = $3 RETURNING *",
        user_id,
        name,
        content_type,
    )
    .fetch_one(db)
    .await
}

pub async fn get_all_encrypted_data_entries_by_user_id(
    user_id: uuid::Uuid,
    db: &sqlx::PgPool,
) -> Result<Vec<EncryptedDataEntry>, sqlx::Error> {
    sqlx::query_as!(
        EncryptedDataEntry,
        "SELECT * FROM encrypted_data_entries WHERE user_id = $1",
        user_id
    )
    .fetch_all(db)
    .await
}
