use crate::test::test;

pub mod test;

#[tokio::main]
async fn main() {
    test().await;
}
