use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

pub async fn test() {
    let route_test = Router::new().route("/test", get(|| async { "test" }));

    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, route_test.into_make_service())
        .await
        .unwrap();
}
