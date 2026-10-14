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

    if let Some(_response_filter) = filter {
        // TODO: only filter successful (2xx) responses, pass error responses through unchanged
        // TODO: buffer the body with a size limit, a response that is too large or a body
        // that can't be filtered (`FilterError`) is an upstream failure: 502, never the unfiltered body
        // TODO: reject a `Content-Encoding` other than identity as upstream failure (502)
        // TODO: after filtering, replace the body and fix/remove `Content-Length` in the parts
        let (_parts, _body) = response.into_parts();
        // TODO: maybe update the signature of response_filter to take a body
        // let body = response_filter.apply(&claim, body);

        todo!("handle body result, send error, or build response with parts")
    }

    Ok(response)
}
