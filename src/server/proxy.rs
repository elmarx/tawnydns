use crate::server::constants::X_API_KEY;
use crate::server::types::TawnyState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, Request, Response, Uri};
use axum::response::IntoResponse;
use http::header;
use http::uri::PathAndQuery;

/// headers that are only meaningful for a single connection and must not be forwarded
/// (RFC 9110 §7.6.1), in addition to the headers named in a `Connection` header
const HOP_BY_HOP: [HeaderName; 9] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    HeaderName::from_static("proxy-connection"),
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("invalid upstream uri")]
    InvalidUri(#[from] http::uri::InvalidUriParts),
    #[error("Upstream PDNS not available")]
    Upstream(#[from] hyper_util::client::legacy::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response<Body> {
        // the source error is only logged, the client gets the generic display message
        tracing::warn!("failed to proxy request: {self:?}");

        Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "error": self.to_string() }).to_string(),
            ))
            .unwrap()
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();

    for name in listed.iter().chain(&HOP_BY_HOP) {
        headers.remove(name);
    }
}

/// the upstream is always `base`, only path and query are taken from the request
fn upstream_uri(base: &Uri, request: &Uri) -> Result<Uri, Error> {
    let mut parts = base.clone().into_parts();
    parts.path_and_query = Some(
        request
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/")),
    );

    Ok(Uri::from_parts(parts)?)
}

async fn forward(s: &TawnyState, mut req: Request<Body>) -> Result<Response<Body>, Error> {
    *req.uri_mut() = upstream_uri(&s.pdns_url, req.uri())?;

    strip_hop_by_hop(req.headers_mut());
    // the client derives the host header from the upstream uri
    req.headers_mut().remove(header::HOST);

    let mut response = s.client.request(req).await?.map(Body::new);
    strip_hop_by_hop(response.headers_mut());

    Ok(response)
}

/// handler that just proxies any request
pub async fn passthrough(State(s): State<TawnyState>, req: Request<Body>) -> Response<Body> {
    forward(&s, req)
        .await
        .unwrap_or_else(IntoResponse::into_response)
}

/// handler that inserts the actual API key
pub async fn sudo_proxy(State(s): State<TawnyState>, mut req: Request<Body>) -> Response<Body> {
    req.headers_mut().insert(X_API_KEY, s.pdns_api_key.clone());

    passthrough(State(s), req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::generate;
    use axum::Router;
    use axum::body::to_bytes;
    use http::{HeaderValue, Method, StatusCode};
    use tower::ServiceExt;

    const PDNS_API_KEY: &str = "actual-key";
    const PATH_QUERY: &str = "/api/v1/servers/localhost/zones?zone=example.com.";

    fn state(pdns_url: &str) -> TawnyState {
        let (_, public_key) = generate().unwrap();
        let public_key = jsonwebtoken::DecodingKey::from_ed_pem(public_key.as_bytes()).unwrap();

        TawnyState::new(
            HeaderValue::from_static(PDNS_API_KEY),
            public_key,
            pdns_url.parse().unwrap(),
        )
    }

    fn joined_header(headers: &http::HeaderMap, name: &str) -> String {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect::<Vec<_>>()
            .join("|")
    }

    /// echoes what the upstream received; `/missing` answers 404,
    /// `/headers` lists the received header names and the host
    async fn echo(req: Request<Body>) -> (StatusCode, String) {
        if req.uri().path() == "/missing" {
            return (StatusCode::NOT_FOUND, "nope".to_string());
        }
        if req.uri().path() == "/headers" {
            let mut names: Vec<_> = req.headers().keys().map(ToString::to_string).collect();
            names.sort();
            let host = joined_header(req.headers(), "host");
            return (
                StatusCode::OK,
                format!("host=[{host}] headers=[{}]", names.join(",")),
            );
        }
        let key = joined_header(req.headers(), "x-api-key");
        let method = req.method().clone();
        let path_query = req.uri().path_and_query().unwrap().to_string();
        let body = to_bytes(req.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        (
            StatusCode::OK,
            format!("{method} {path_query} key=[{key}] body=[{body}]"),
        )
    }

    async fn hop_by_hop_response() -> ([(&'static str, &'static str); 5], &'static str) {
        (
            [
                ("keep-alive", "timeout=5"),
                ("proxy-authenticate", "Basic"),
                ("proxy-connection", "keep-alive"),
                ("upgrade", "websocket"),
                ("x-custom", "kept"),
            ],
            "ok",
        )
    }

    async fn echo_body(req: Request<Body>) -> Response<Body> {
        Response::new(req.into_body())
    }

    async fn seen_method(req: Request<Body>) -> ([(&'static str, String); 1], String) {
        let method = req.method().to_string();
        ([("x-seen-method", method.clone())], method)
    }

    async fn status(axum::extract::Path(code): axum::extract::Path<u16>) -> StatusCode {
        StatusCode::from_u16(code).unwrap()
    }

    async fn redirect() -> Response<Body> {
        Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/elsewhere")
            .body(Body::empty())
            .unwrap()
    }

    async fn cookies() -> Response<Body> {
        Response::builder()
            .header(header::SET_COOKIE, "a=1")
            .header(header::SET_COOKIE, "b=2")
            .body(Body::empty())
            .unwrap()
    }

    async fn multi_header(req: Request<Body>) -> String {
        joined_header(req.headers(), "x-multi")
    }

    /// every byte value, announced as compressed: must be passed back untouched
    fn binary_payload() -> Vec<u8> {
        (0..=255u8).cycle().take(4096).collect()
    }

    async fn binary() -> Response<Body> {
        Response::builder()
            .header(header::CONTENT_ENCODING, "gzip")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(binary_payload()))
            .unwrap()
    }

    async fn mock_upstream() -> String {
        use axum::routing::any;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let upstream = Router::new()
            .route("/hop-by-hop-response", any(hop_by_hop_response))
            .route("/echo-body", any(echo_body))
            .route("/method", any(seen_method))
            .route("/status/{code}", any(status))
            .route("/redirect", any(redirect))
            .route("/cookies", any(cookies))
            .route("/multi-header", any(multi_header))
            .route("/binary", any(binary))
            .fallback(echo);
        tokio::spawn(async move { axum::serve(listener, upstream).await });

        format!("http://{addr}")
    }

    /// upstream that reads one chunk of each connection, answers with the given
    /// raw bytes and closes the connection
    async fn raw_upstream(response: &'static [u8]) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket.write_all(response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        format!("http://{addr}")
    }

    async fn body_string(response: Response<Body>) -> String {
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(body.to_vec()).unwrap()
    }

    fn passthrough_app(state: TawnyState) -> Router {
        Router::new().fallback(passthrough).with_state(state)
    }

    #[tokio::test]
    async fn forwards_method_path_query_headers_and_body_unchanged() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .method(Method::PATCH)
            .uri(PATH_QUERY)
            .header(X_API_KEY, "client-key")
            .body(Body::from(r#"{"rrsets":[]}"#))
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(actual.status(), StatusCode::OK);
        let actual = body_string(actual).await;
        let expected = format!(r#"PATCH {PATH_QUERY} key=[client-key] body=[{{"rrsets":[]}}]"#);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn upstream_status_and_body_are_passed_back() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .uri("/missing")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(actual.status(), StatusCode::NOT_FOUND);
        assert_eq!(body_string(actual).await, "nope");
    }

    #[tokio::test]
    async fn unreachable_upstream_is_502_json_error() {
        // nothing listens on port 1
        let sample = state("http://127.0.0.1:1");
        let request = Request::builder()
            .uri(PATH_QUERY)
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(actual.status(), StatusCode::BAD_GATEWAY);
        let content_type = actual.headers().get(header::CONTENT_TYPE);
        assert_eq!(content_type.unwrap(), "application/json");
        let actual = body_string(actual).await;
        let actual: serde_json::Value = serde_json::from_str(&actual).unwrap();
        assert!(actual["error"].is_string());
    }

    #[tokio::test]
    async fn unusable_upstream_url_is_502_instead_of_panic() {
        // no scheme/authority: cannot be used as base for the upstream uri
        let sample = state("/relative");
        let request = Request::builder()
            .uri(PATH_QUERY)
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(actual.status(), StatusCode::BAD_GATEWAY);
    }

    fn proxy_app(state: TawnyState) -> Router {
        Router::new().fallback(sudo_proxy).with_state(state)
    }

    #[tokio::test]
    async fn client_supplied_keys_are_replaced_by_the_actual_key() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .method(Method::POST)
            .uri(PATH_QUERY)
            .header(X_API_KEY, "first")
            .header(X_API_KEY, "second")
            .body(Body::from("payload"))
            .unwrap();

        let actual = proxy_app(sample).oneshot(request).await.unwrap();

        let actual = body_string(actual).await;
        let expected = format!("POST {PATH_QUERY} key=[{PDNS_API_KEY}] body=[payload]");
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn hop_by_hop_request_headers_are_not_forwarded() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .uri("/headers")
            .header("connection", "x-listed, keep-alive")
            .header("x-listed", "named by the connection header")
            .header("keep-alive", "timeout=5")
            .header("upgrade", "websocket")
            .header("te", "trailers")
            .header("proxy-authorization", "Basic abc")
            .header("proxy-connection", "keep-alive")
            .header("x-custom", "kept")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        let actual = body_string(actual).await;
        let (_, actual) = actual.split_once("headers=[").unwrap();
        let actual: Vec<_> = actual.trim_end_matches(']').split(',').collect();
        assert!(actual.contains(&"x-custom"), "{actual:?}");
        for hop_by_hop in [
            "connection",
            "x-listed",
            "keep-alive",
            "upgrade",
            "te",
            "proxy-authorization",
            "proxy-connection",
        ] {
            assert!(!actual.contains(&hop_by_hop), "{hop_by_hop}: {actual:?}");
        }
    }

    #[tokio::test]
    async fn headers_named_by_the_connection_header_are_not_forwarded() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .uri("/headers")
            .header("connection", "X-Foo ,x-bar")
            .header("connection", "x-baz")
            .header("x-foo", "1")
            .header("x-bar", "2")
            .header("x-baz", "3")
            .header("x-unlisted", "kept")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        let actual = body_string(actual).await;
        let (_, actual) = actual.split_once("headers=[").unwrap();
        let actual: Vec<_> = actual.trim_end_matches(']').split(',').collect();
        assert!(actual.contains(&"x-unlisted"), "{actual:?}");
        for listed in ["x-foo", "x-bar", "x-baz"] {
            assert!(!actual.contains(&listed), "{listed}: {actual:?}");
        }
    }

    #[tokio::test]
    async fn host_header_of_the_client_is_replaced_by_the_upstream_authority() {
        let upstream = mock_upstream().await;
        let sample = state(&upstream);
        let request = Request::builder()
            .uri("/headers")
            .header(header::HOST, "dns.example.com")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        let actual = body_string(actual).await;
        let authority = upstream.trim_start_matches("http://");
        assert!(
            actual.starts_with(&format!("host=[{authority}]")),
            "{actual}"
        );
    }

    #[tokio::test]
    async fn hop_by_hop_response_headers_are_not_passed_back() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .uri("/hop-by-hop-response")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(actual.headers().get("x-custom").unwrap(), "kept");
        for hop_by_hop in [
            "keep-alive",
            "proxy-authenticate",
            "proxy-connection",
            "upgrade",
        ] {
            assert!(actual.headers().get(hop_by_hop).is_none(), "{hop_by_hop}");
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn path_and_query_are_forwarded_byte_for_byte() {
        let upstream = mock_upstream().await;
        let samples = [
            "/a%2Fb/c",
            "/zones/example.com./rrsets?x=a%20b&y=%C3%A9",
            "//double//slash",
            "/path?",
            "/p?a=1&a=2&b",
            "/%7Euser",
            "/a/./b/../c",
            "/?api-key=from-query",
        ];

        for sample in samples {
            let actual = passthrough_app(state(&upstream))
                .oneshot(get(sample))
                .await
                .unwrap();

            let actual = body_string(actual).await;
            let expected = format!("GET {sample} key=[] body=[]");
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn absolute_request_uri_never_changes_the_destination() {
        let sample = state(&mock_upstream().await);

        // nothing listens on port 1: following the request's authority would give a 502
        let actual = passthrough_app(sample)
            .oneshot(get("http://127.0.0.1:1/zones?x=1"))
            .await
            .unwrap();

        assert_eq!(actual.status(), StatusCode::OK);
        let actual = body_string(actual).await;
        assert_eq!(actual, "GET /zones?x=1 key=[] body=[]");
    }

    #[tokio::test]
    async fn trailing_slash_in_upstream_url_is_harmless() {
        let sample = state(&format!("{}/", mock_upstream().await));

        let actual = passthrough_app(sample)
            .oneshot(get(PATH_QUERY))
            .await
            .unwrap();

        let actual = body_string(actual).await;
        assert_eq!(actual, format!("GET {PATH_QUERY} key=[] body=[]"));
    }

    #[tokio::test]
    async fn all_methods_are_forwarded() {
        let upstream = mock_upstream().await;

        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ] {
            let request = Request::builder()
                .method(method.clone())
                .uri("/method")
                .body(Body::empty())
                .unwrap();

            let actual = passthrough_app(state(&upstream))
                .oneshot(request)
                .await
                .unwrap();

            let seen = actual.headers().get("x-seen-method").unwrap();
            assert_eq!(seen, method.as_str());
        }
    }

    #[tokio::test]
    async fn binary_request_and_response_bodies_are_untouched() {
        let sample = state(&mock_upstream().await);
        let payload = binary_payload();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/echo-body")
            .body(Body::from(payload.clone()))
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        let actual = to_bytes(actual.into_body(), usize::MAX).await.unwrap();
        assert_eq!(actual.as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn large_bodies_are_not_truncated() {
        let sample = state(&mock_upstream().await);
        #[allow(clippy::cast_sign_loss)]
        let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/echo-body")
            .body(Body::from(payload.clone()))
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        let actual = to_bytes(actual.into_body(), usize::MAX).await.unwrap();
        assert_eq!(actual.as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn compressed_response_is_passed_back_untouched_with_its_headers() {
        let sample = state(&mock_upstream().await);

        let actual = passthrough_app(sample)
            .oneshot(get("/binary"))
            .await
            .unwrap();

        let headers = actual.headers();
        assert_eq!(headers.get(header::CONTENT_ENCODING).unwrap(), "gzip");
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        let actual = to_bytes(actual.into_body(), usize::MAX).await.unwrap();
        assert_eq!(actual.as_ref(), binary_payload().as_slice());
    }

    #[tokio::test]
    async fn chunked_response_is_passed_back_complete() {
        let upstream = raw_upstream(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .await;

        let actual = passthrough_app(state(&upstream))
            .oneshot(get(PATH_QUERY))
            .await
            .unwrap();

        assert_eq!(actual.status(), StatusCode::OK);
        assert_eq!(body_string(actual).await, "hello world");
    }

    #[tokio::test]
    async fn status_codes_are_passed_back_unchanged() {
        let upstream = mock_upstream().await;

        for code in [200u16, 201, 204, 400, 401, 403, 404, 409, 422, 500, 503] {
            let actual = passthrough_app(state(&upstream))
                .oneshot(get(&format!("/status/{code}")))
                .await
                .unwrap();

            assert_eq!(actual.status().as_u16(), code);
        }
    }

    #[tokio::test]
    async fn redirects_are_passed_back_not_followed() {
        let sample = state(&mock_upstream().await);

        let actual = passthrough_app(sample)
            .oneshot(get("/redirect"))
            .await
            .unwrap();

        assert_eq!(actual.status(), StatusCode::FOUND);
        assert_eq!(
            actual.headers().get(header::LOCATION).unwrap(),
            "/elsewhere"
        );
    }

    #[tokio::test]
    async fn repeated_response_headers_are_all_passed_back() {
        let sample = state(&mock_upstream().await);

        let actual = passthrough_app(sample)
            .oneshot(get("/cookies"))
            .await
            .unwrap();

        let actual: Vec<_> = actual
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(actual, ["a=1", "b=2"]);
    }

    #[tokio::test]
    async fn repeated_request_headers_are_all_forwarded() {
        let sample = state(&mock_upstream().await);
        let request = Request::builder()
            .uri("/multi-header")
            .header("x-multi", "one")
            .header("x-multi", "two")
            .body(Body::empty())
            .unwrap();

        let actual = passthrough_app(sample).oneshot(request).await.unwrap();

        assert_eq!(body_string(actual).await, "one|two");
    }

    #[tokio::test]
    async fn concurrent_requests_do_not_get_mixed_up() {
        let sample = state(&mock_upstream().await);
        let mut tasks = tokio::task::JoinSet::new();

        for i in 0..64 {
            let app = passthrough_app(sample.clone());
            tasks.spawn(async move {
                let payload = format!("payload-{i}");
                let request = Request::builder()
                    .method(Method::POST)
                    .uri("/echo-body")
                    .body(Body::from(payload.clone()))
                    .unwrap();

                let actual = app.oneshot(request).await.unwrap();

                (payload, body_string(actual).await)
            });
        }

        while let Some(result) = tasks.join_next().await {
            let (expected, actual) = result.unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn upstream_closing_the_connection_after_each_response_is_handled() {
        let upstream =
            raw_upstream(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok")
                .await;
        let sample = state(&upstream);

        // the pooled connection of the first request is dead for the next ones
        for _ in 0..5 {
            let actual = passthrough_app(sample.clone())
                .oneshot(get(PATH_QUERY))
                .await
                .unwrap();

            assert_eq!(actual.status(), StatusCode::OK);
            assert_eq!(body_string(actual).await, "ok");
        }
    }

    #[tokio::test]
    async fn broken_upstreams_are_502_with_the_same_generic_body() {
        let upstreams = [
            // closes without answering
            raw_upstream(b"").await,
            // does not speak http
            raw_upstream(b"not http at all\r\n\r\n").await,
            // headers cut off
            raw_upstream(b"HTTP/1.1 200 OK\r\nContent-Le").await,
            // nothing listens
            "http://127.0.0.1:1".to_string(),
        ];

        let mut actual = Vec::new();
        for upstream in upstreams {
            let response = passthrough_app(state(&upstream))
                .oneshot(get(PATH_QUERY))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::BAD_GATEWAY, "{upstream}");
            actual.push(body_string(response).await);
        }

        assert!(actual.windows(2).all(|w| w[0] == w[1]), "{actual:?}");
        // no internals (addresses, os errors) in what the client sees
        for body in actual {
            assert!(!body.contains("127.0.0.1"), "{body}");
            assert!(!body.to_lowercase().contains("refused"), "{body}");
            assert!(!body.contains("os error"), "{body}");
        }
    }

    #[tokio::test]
    async fn truncated_upstream_body_is_an_error_not_a_complete_response() {
        let upstream =
            raw_upstream(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly a few bytes").await;

        let actual = passthrough_app(state(&upstream))
            .oneshot(get(PATH_QUERY))
            .await
            .unwrap();

        let actual = to_bytes(actual.into_body(), usize::MAX).await;
        assert!(actual.is_err());
    }
}
