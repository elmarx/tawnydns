use crate::claim::Claim;
use crate::jwt;
use crate::server::constants::X_API_KEY;
use crate::server::proxy;
use crate::server::types::TawnyState;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use http::{HeaderMap, Response};
use jsonwebtoken::TokenData;
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub enum Principal {
    Admin,
    Token(Claim),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("No X-API-Key header given")]
    NoApiKeyGiven,
    #[error("Invalid X-API-Key given")]
    InvalidApiKey(#[from] jsonwebtoken::errors::Error),
    #[error("Multiple X-API-Key headers given")]
    MultipleHeadersGiven,
    // TODO: add more detailed error types (NotAJwt, by calling decode_header first) etc.
}

fn identify(headers: &HeaderMap, s: &TawnyState) -> Result<Principal, Error> {
    if 1 < headers.get_all(X_API_KEY).iter().count() {
        return Err(Error::MultipleHeadersGiven);
    }

    match headers.get(X_API_KEY) {
        // use constant-time comparison to mitigate timing attacks
        Some(api_key) if api_key.as_bytes().ct_eq(s.pdns_api_key.as_bytes()).into() => {
            Ok(Principal::Admin)
        }
        // TODO: return more detailed error types (NotAJwt, by calling decode_header first) etc.
        Some(api_key) => match jwt::decode::<Claim>(&s.public_key, api_key) {
            Ok(TokenData { claims, .. }) => Ok(Principal::Token(claims)),
            Err(e) => Err(Error::InvalidApiKey(e)),
        },
        None => Err(Error::NoApiKeyGiven),
    }
}

pub async fn authenticate_middleware(
    State(s): State<TawnyState>,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    let principal = identify(req.headers(), &s);

    match principal {
        Ok(Principal::Admin) => proxy::passthrough(State(s), req).await,
        Ok(Principal::Token(claim)) => {
            req.extensions_mut().insert(claim);
            next.run(req).await
        }
        // TODO: based on extended error types, log more detailed error messages
        Err(_e) => Response::builder()
            .status(http::StatusCode::UNAUTHORIZED)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"error":"Unauthorized"}"#))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::fixtures::claim;
    use crate::keygen::generate;
    use crate::permissions::fixtures::owner;
    use axum::Router;
    use axum::body::to_bytes;
    use axum::middleware;
    use http::{HeaderValue, StatusCode};
    use jsonwebtoken::EncodingKey;
    use tower::ServiceExt;

    const PDNS_API_KEY: &str = "actual-key";
    const PATH_QUERY: &str = "/api/v1/servers/localhost/zones?zone=example.com.";

    fn state() -> (TawnyState, EncodingKey) {
        let (private_key, public_key) = generate().unwrap();

        let decoding_key = jsonwebtoken::DecodingKey::from_ed_pem(public_key.as_bytes()).unwrap();
        let encoding_key = jsonwebtoken::EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap();

        (
            TawnyState::new(
                HeaderValue::from_static(PDNS_API_KEY),
                decoding_key,
                http::Uri::from_static("http://127.0.0.1:1"),
            ),
            encoding_key,
        )
    }

    fn headers(name: &str, value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    /// a token owning `zone` (given without trailing dot)
    fn sign(key: &EncodingKey, zone: &str) -> String {
        let claim = claim(vec![owner(zone)]);
        jwt::encode(key, &claim).unwrap()
    }

    mod identify {
        use super::*;

        #[test]
        fn actual_key_is_admin() {
            let sample = headers(X_API_KEY, PDNS_API_KEY);

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Ok(Principal::Admin)));
        }

        #[test]
        fn missing_key_is_rejected() {
            let sample = HeaderMap::new();

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Err(Error::NoApiKeyGiven)));
        }

        #[test]
        fn header_name_is_case_insensitive() {
            let sample = headers("x-aPi-kEy", PDNS_API_KEY);

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Ok(Principal::Admin)));
        }

        #[test]
        fn multiple_api_key_headers_are_rejected() {
            let samples = [
                ["wrong", PDNS_API_KEY],
                [PDNS_API_KEY, "wrong"],
                [PDNS_API_KEY, PDNS_API_KEY],
            ];

            for sample in samples {
                let mut headers = HeaderMap::new();
                for value in sample {
                    headers.append(X_API_KEY, HeaderValue::from_static(value));
                }

                let actual = identify(&headers, &state().0);

                assert!(
                    matches!(actual, Err(Error::MultipleHeadersGiven)),
                    "{sample:?}"
                );
            }
        }

        #[test]
        fn near_misses_of_the_actual_key_are_rejected() {
            let samples = [
                "",
                "actual-ke",
                "actual-key ",
                " actual-key",
                "ACTUAL-KEY",
                "actual-key2",
            ];

            for sample in samples {
                let sample = headers(X_API_KEY, sample);

                let actual = identify(&sample, &state().0);

                assert!(matches!(actual, Err(Error::InvalidApiKey(_))), "{sample:?}");
            }
        }

        #[test]
        fn non_ascii_key_is_rejected() {
            let mut sample = HeaderMap::new();
            sample.insert(X_API_KEY, HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
        }

        #[test]
        fn valid_token_is_identified_with_its_claim() {
            let (state, encoding_key) = state();
            let sample = headers(X_API_KEY, &sign(&encoding_key, "example.com"));

            let actual = identify(&sample, &state);

            let Ok(Principal::Token(actual)) = actual else {
                panic!("expected a token principal");
            };
            assert_eq!(actual, claim(vec![owner("example.com")]));
        }

        #[test]
        fn token_signed_by_other_key_is_rejected() {
            let (_, other_encoding_key) = state();
            let sample = headers(X_API_KEY, &sign(&other_encoding_key, "example.com"));

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
        }

        #[test]
        fn token_with_tampered_payload_is_rejected() {
            let (state, encoding_key) = state();
            let token = sign(&encoding_key, "example.com");
            let forged = sign(&encoding_key, "other.org");
            // header and signature of the first token, payload of the second
            let parts = |t: &str| t.split('.').map(String::from).collect::<Vec<_>>();
            let (token, forged) = (parts(&token), parts(&forged));
            let sample = headers(
                X_API_KEY,
                &format!("{}.{}.{}", token[0], forged[1], token[2]),
            );

            let actual = identify(&sample, &state);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
        }

        #[test]
        fn token_with_other_algorithm_is_rejected() {
            let (state, _) = state();
            let claim = claim(vec![owner("example.com")]);
            let hmac_key = jsonwebtoken::EncodingKey::from_secret(b"secret");
            let token =
                jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claim, &hmac_key).unwrap();
            let sample = headers(X_API_KEY, &token);

            let actual = identify(&sample, &state);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
        }

        #[test]
        fn unsigned_token_is_rejected() {
            // {"alg":"none","typ":"JWT"} . {"z":["example.com."]} .
            let sample = headers(
                X_API_KEY,
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ6IjpbImV4YW1wbGUuY29tLiJdfQ.",
            );

            let actual = identify(&sample, &state().0);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
        }

        #[test]
        fn malformed_tokens_are_rejected() {
            let samples = ["garbage", "a.b.c", "..", "a.b"];

            for sample in samples {
                let sample = headers(X_API_KEY, sample);

                let actual = identify(&sample, &state().0);

                assert!(matches!(actual, Err(Error::InvalidApiKey(_))), "{sample:?}");
            }
        }

        #[test]
        fn token_with_unexpected_claims_is_rejected() {
            let (state, encoding_key) = state();
            let token =
                jwt::encode(&encoding_key, &serde_json::json!({ "sub": "example.com." })).unwrap();
            let sample = headers(X_API_KEY, &token);

            let actual = identify(&sample, &state);

            assert!(matches!(actual, Err(Error::InvalidApiKey(_))));
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
            let mut sample = state().0;
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

        async fn body_string(response: Response<Body>) -> String {
            let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        }

        #[tokio::test]
        async fn missing_key_is_401_without_calling_next() {
            let sample = request(None);

            let actual = app(state().0).oneshot(sample).await.unwrap();

            assert_eq!(actual.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn rejections_are_401_json_errors() {
            let (_, other_key) = state();
            let (state, _) = state();
            let samples = [
                request(None),
                request(Some("garbage")),
                request(Some(&sign(&other_key, "example.com"))),
            ];

            for sample in samples {
                let actual = app(state.clone()).oneshot(sample).await.unwrap();

                assert_eq!(actual.status(), StatusCode::UNAUTHORIZED);
                let content_type = actual.headers().get(http::header::CONTENT_TYPE);
                assert_eq!(content_type.unwrap(), "application/json");
                let actual = body_string(actual).await;
                let actual: serde_json::Value = serde_json::from_str(&actual).unwrap();
                assert!(actual["error"].is_string());
            }
        }

        #[tokio::test]
        async fn error_body_does_not_reveal_why_a_token_was_rejected() {
            let (_, other_key) = state();
            let (state, _) = state();
            let samples = [
                request(Some("garbage")),
                request(Some(&sign(&other_key, "example.com"))),
            ];

            let mut actual = Vec::new();
            for sample in samples {
                let response = app(state.clone()).oneshot(sample).await.unwrap();
                actual.push(body_string(response).await);
            }

            assert_eq!(actual[0], actual[1]);
        }

        #[tokio::test]
        async fn multiple_api_key_headers_are_401() {
            let mut sample = request(Some(PDNS_API_KEY));
            sample
                .headers_mut()
                .append(X_API_KEY, HeaderValue::from_static(PDNS_API_KEY));

            let actual = app(state().0).oneshot(sample).await.unwrap();

            assert_eq!(actual.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        async fn valid_token_calls_next() {
            let (state, encoding_key) = state();
            let sample = request(Some(&sign(&encoding_key, "example.com")));

            let actual = app(state).oneshot(sample).await.unwrap();

            assert_eq!(actual.status(), StatusCode::IM_A_TEAPOT);
        }

        #[tokio::test]
        async fn valid_token_hands_principal_to_next() {
            let (state, encoding_key) = state();
            let sample = request(Some(&sign(&encoding_key, "example.com")));
            let app = Router::new()
                .fallback(
                    |axum::Extension(claim): axum::Extension<Claim>| async move {
                        serde_json::to_string(&claim).unwrap()
                    },
                )
                .layer(middleware::from_fn_with_state(
                    state,
                    authenticate_middleware,
                ));

            let actual = app.oneshot(sample).await.unwrap();

            let actual = body_string(actual).await;
            assert_eq!(actual, r#"{"1":[{"o":"example.com"}]}"#);
        }
    }
}
