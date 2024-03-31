use crate::model::User;

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
