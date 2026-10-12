use crate::server::constants::X_API_KEY;
use crate::server::proxy;
use crate::server::types::TawnyState;
use crate::token::Claim;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use http::{HeaderMap, Response};
use subtle::ConstantTimeEq;

pub enum Principal {
    Admin,
    Token(Claim),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No X-API-Key header given")]
    NoApiKeyGiven,
    #[error("Invalid X-API-Key given")]
    InvalidApiKey,
}

fn identify(headers: &HeaderMap, s: &TawnyState) -> Result<Principal, Error> {
    match headers.get(X_API_KEY) {
        // use constant-time comparison to mitigate timing attacks
        Some(api_key) if api_key.as_bytes().ct_eq(s.pdns_api_key.as_bytes()).into() => {
            Ok(Principal::Admin)
        }
        Some(_api_key) => todo!("check/decode/validate JWT"),
        None => Err(Error::NoApiKeyGiven),
    }
}

pub async fn authenticate_middleware(
    State(s): State<TawnyState>,
    req: Request,
    _next: Next,
) -> Response<Body> {
    let principal = identify(req.headers(), &s);

    match principal {
        Ok(Principal::Admin) => proxy::passthrough(State(s), req).await,
        Ok(Principal::Token(_token)) => {
            todo!("next")
        }
        Err(_e) => {
            todo!("401")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::to_bytes;
    use axum::middleware;
    use http::{HeaderValue, StatusCode};
    use tower::ServiceExt;

    const PDNS_API_KEY: &str = "actual-key";
    const PATH_QUERY: &str = "/api/v1/servers/localhost/zones?zone=example.com.";

    fn state() -> TawnyState {
        TawnyState::new(HeaderValue::from_static(PDNS_API_KEY))
    }

    fn headers(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    mod identify {
        use super::*;

        #[test]
        fn actual_key_is_admin() {
            let sample = headers(X_API_KEY, PDNS_API_KEY);

            let actual = identify(&sample, &state());

            assert!(matches!(actual, Ok(Principal::Admin)));
        }

        #[test]
        fn missing_key_is_rejected() {
            let sample = HeaderMap::new();

            let actual = identify(&sample, &state());

            assert!(matches!(actual, Err(Error::NoApiKeyGiven)));
        }

        #[test]
        fn header_name_is_case_insensitive() {
            let sample = headers("x-aPi-kEy", PDNS_API_KEY);

            let actual = identify(&sample, &state());

            assert!(matches!(actual, Ok(Principal::Admin)));
        }
    }

    mod authenticate_middleware_tests {
        use super::*;

        /// router whose only handler answers 418, to detect that `next` was called
        fn app(state: TawnyState) -> Router {
            Router::new()
                .fallback(|| async { StatusCode::IM_A_TEAPOT })
                .layer(middleware::from_fn_with_state(
                    state,
                    authenticate_middleware,
                ))
        }

        fn request(api_key: Option<&str>) -> Request {
            let mut builder = Request::builder().uri(PATH_QUERY);
            if let Some(api_key) = api_key {
                builder = builder.header(X_API_KEY, api_key);
            }
            builder.body(Body::empty()).unwrap()
        }

        /// upstream that echoes the received api key and path+query
        async fn mock_upstream() -> http::Uri {
            let upstream = Router::new().fallback(|req: Request| async move {
                let key = req.headers().get(X_API_KEY).map(|k| k.to_str().unwrap());
                let path_query = req.uri().path_and_query().unwrap();
                format!("upstream:{}:{path_query}", key.unwrap_or("<none>"))
            });
            // let tokio choose a random port
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, upstream).await });

            format!("http://{addr}").parse().unwrap()
        }

        #[tokio::test]
        async fn actual_key_is_forwarded_unchanged_without_calling_next() {
            let mut sample = state();
            sample.pdns_url = mock_upstream().await;

            let actual = app(sample)
                .oneshot(request(Some(PDNS_API_KEY)))
                .await
                .unwrap();

            assert_eq!(actual.status(), StatusCode::OK);
            let actual = to_bytes(actual.into_body(), usize::MAX).await.unwrap();
            let actual = String::from_utf8(actual.to_vec()).unwrap();
            let expected = format!("upstream:{PDNS_API_KEY}:{PATH_QUERY}");
            assert_eq!(actual, expected);
        }
    }
}
