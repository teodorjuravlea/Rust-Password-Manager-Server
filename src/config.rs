pub async fn get_database_url() -> String {
    std::env::var("DATABASE_URL").expect("Database URL not present in environment")
}
