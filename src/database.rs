use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn initialize_database(database_url: String) -> PgPool {
    // Create a database connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url.as_str())
        .await
        .unwrap();

    // Run the migrations
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();

    pool
}

pub async fn create_user(pool: &PgPool, email: &str, password: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO users (email, password)
        VALUES ($1, $2)
        "#,
        email,
        password
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_user(pool: &PgPool, user_id: i32) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM users
        WHERE id = $1
        "#,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn get_user_id_from_email(pool: &PgPool, email: &str) -> Result<i32, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        SELECT id
        FROM users
        WHERE email = $1
        "#,
        email
    )
    .fetch_one(pool)
    .await?;

    Ok(result.id)
}

pub async fn get_user_password(pool: &PgPool, id: i32) -> Result<String, sqlx::Error> {
    let result = sqlx::query!(
        r#"
        SELECT password
        FROM users
        WHERE id = $1
        "#,
        id
    )
    .fetch_one(pool)
    .await?;

    Ok(result.password)
}

pub async fn create_session(pool: &PgPool, user_id: i32, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO sessions (user_id, token)
        VALUES ($1, $2)
        "#,
        user_id,
        token
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_session(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        DELETE FROM sessions
        WHERE token = $1
        "#,
        token
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn change_password(
    pool: &PgPool,
    user_id: i32,
    new_password: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE users
        SET password = $1
        WHERE id = $2
        "#,
        new_password,
        user_id
    )
    .execute(pool)
    .await?;

    Ok(())
}
