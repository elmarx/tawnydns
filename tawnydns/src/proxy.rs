use crate::{ACTUAL_API_KEY, Client, X_API_KEY};
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, Uri};
use axum::response::IntoResponse;

/// handler that just proxies any request
pub async fn proxy_handler(State(client): State<Client>, mut req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    client.request(req).await.unwrap().into_response()
}

/// handler that inserts the actual API key
pub async fn authorized_proxy_handler(
    State(client): State<Client>,
    mut req: Request<Body>,
) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    req.headers_mut().remove(X_API_KEY);
    req.headers_mut()
        .insert(X_API_KEY, ACTUAL_API_KEY.try_into().unwrap());

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    client.request(req).await.unwrap().into_response()
}
