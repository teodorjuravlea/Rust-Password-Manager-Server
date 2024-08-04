use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderValue, Method,
};
use config::Config;
use dotenv::dotenv;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::api::create_api_router;

mod api;
mod authentication;
mod config;
mod database;
mod handler;
mod model;
mod utils;

pub struct AppState {
    db: PgPool,
    config: Config,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Load config from environment variables
    dotenv().ok();
    let config = Config::init();

    // Initialize database connection pool
    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await
    {
        Ok(pool) => {
            println!("Connected to database");
            pool
        }
        Err(e) => {
            println!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize server
    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    let app = create_api_router(Arc::new(AppState { db: pool, config })).layer(cors);

    println!("Server started!");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
