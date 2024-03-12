pub mod api;
pub mod authentication;
pub mod config;
pub mod database;
pub mod encryption;
pub mod tests;

use database::initialize_database;
use tests::test::test;

#[tokio::main]
async fn main() {
    // Run the test
    // test().await;

    // Get config
    let database_url = config::get_database_url().await;

    // Initialize database
    let pool = initialize_database(database_url).await;
}
