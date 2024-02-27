pub mod tests;

use tests::test::test;

#[tokio::main]
async fn main() {
    test().await;
}
