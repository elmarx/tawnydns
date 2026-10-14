use crate::pdns_api::Route;
use crate::policy::{self, Grant};
use crate::server::error::Error;
use crate::server::proxy::sudo_proxy;
use crate::server::types::TawnyState;
use crate::token::Claim;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response};

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

    let req = if let Some(body_check) = body_condition {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1024 * 1024)
            .await
            .map_err(|_e| {
                // TODO: distinguish reaching the limit — 413 and normal "read error"
                // TODO: log the error
                Error::InvalidRequestBody
            })?;

        body_check.apply(&claim, &bytes)?;
        Request::from_parts(parts, Body::from(bytes))
    } else {
        req
    };

    // TODO: if `filter` is set, remove `Accept-Encoding` from the request before forwarding,
    // otherwise pdns may compress the response and the filter can't parse it
    let response = sudo_proxy(State(state), req).await;

    // filter 2xx responses, others will be passed through
    let response = if let Some(response_filter) = filter
        && response.status().is_success()
    {
        let (mut parts, body) = response.into_parts();
        // TODO: properly implement error handling instead of unwrap: 502
        let body = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();

        // TODO: properly implement error handling instead of unwrap: 502
        let filtered_response = response_filter.apply(&claim, &body).unwrap();

        // remove the content-length (since we have filtered the body)
        parts.headers.remove(http::header::CONTENT_LENGTH);

        Response::from_parts(parts, Body::from(filtered_response))
    } else {
        response
    };

    Ok(response)
}
