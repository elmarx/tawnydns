use axum::routing::{any, post};
use axum::{Router, middleware};
use eros::{AnyError, Context};
use http::HeaderValue;
use jsonwebtoken::DecodingKey;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;
use tracing::Level;
use types::TawnyState;

mod authenticate;
mod constants;
mod handler;
mod proxy;
mod types;

pub async fn run(pdns_api_key: HeaderValue, public_key: PathBuf) -> eros::Result<(), AnyError> {
    let public_key = tokio::fs::read(&public_key)
        .await
        .context("read public key")?;
    let public_key = DecodingKey::from_ed_pem(&public_key).context("decode public key")?;

    let state = TawnyState::new(pdns_api_key, public_key);

    let app = Router::new()
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}/{*path}",
            any(handler::zone_path),
        )
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}",
            any(handler::zone_root),
        )
        .route(
            "/api/v1/servers/localhost/zones",
            post(handler::create_zone).fallback(proxy::passthrough),
        )
        .route("/api/v1/servers", any(proxy::sudo_proxy))
        .route("/api/v1/servers/{server}", any(proxy::sudo_proxy))
        .fallback(proxy::passthrough)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authenticate::authenticate_middleware,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .context("binding tcp listener")?;

    axum::serve(listener, app).await.context("axum serve")?;

    Ok(())
}
