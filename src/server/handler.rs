use crate::content_type;
use crate::pdns::Route;
use crate::policy::{self, Grant};
use crate::server::error::Error;
use crate::server::proxy::sudo_proxy;
use crate::server::types::TawnyState;
use crate::token::Claim;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response};

const MAX_REQUEST_BODY: usize = 1024 * 1024;

pub async fn handle(
    State(state): State<TawnyState>,
    axum::Extension(claim): axum::Extension<Claim>,
    req: Request<Body>,
) -> Result<Response<Body>, Error> {
    let route = Route::try_from(&req)?;
    let Grant {
        body_condition,
        filter,
    } = policy::authorize(&claim, &route)?;

    let mut req = if let Some(body_check) = body_condition {
        let (parts, body) = req.into_parts();

        // checked before buffering the body
        content_type::verify_json(&parts.headers)?;

        let bytes = axum::body::to_bytes(body, MAX_REQUEST_BODY)
            .await
            .map_err(|e| Error::from_request_body(&e))?;

        body_check.apply(&claim, &bytes)?;
        Request::from_parts(parts, Body::from(bytes))
    } else {
        req
    };

    if filter.is_some() {
        // pdns might compress the response if we forward the Accept-Encoding header and that makes inspecting the response difficult
        req.headers_mut().remove(http::header::ACCEPT_ENCODING);
    }

    let response = sudo_proxy(State(state), req).await;

    // filter 2xx responses, others will be passed through
    let response = if let Some(response_filter) = filter
        && response.status().is_success()
    {
        let (mut parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .map_err(Error::UpstreamBody)?;

        let filtered_response = response_filter.apply(&claim, &body)?;

        // remove the content-length and etag (since we have filtered/modified the body)
        parts.headers.remove(http::header::CONTENT_LENGTH);
        parts.headers.remove(http::header::ETAG);

        Response::from_parts(parts, Body::from(filtered_response))
    } else {
        response
    };

    Ok(response)
}
