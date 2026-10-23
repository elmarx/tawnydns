use crate::server::authenticate;
use crate::server::handler::handle;
use crate::server::types::TawnyState;
use axum::{Router, middleware};
use eros::{AnyError, Context};
use http::{HeaderValue, Uri};
use jsonwebtoken::DecodingKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower_http::trace::TraceLayer;
use tracing::Level;

pub async fn run(
    pdns_api_key: HeaderValue,
    public_key: PathBuf,
    listen: SocketAddr,
    pdns_url: Uri,
) -> eros::Result<(), AnyError> {
    let public_key = tokio::fs::read(&public_key)
        .await
        .context("read public key")?;
    let public_key = DecodingKey::from_ed_pem(&public_key).context("decode public key")?;

    let state = TawnyState::new(pdns_api_key, public_key, pdns_url);

    let app = Router::new()
        .fallback(handle)
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

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .context("binding tcp listener")?;

    axum::serve(listener, app).await.context("axum serve")?;

    Ok(())
}
