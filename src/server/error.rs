use crate::pdns_api::RouteError;
use crate::policy;
use crate::policy::Denied;
use axum::response::IntoResponse;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Route malformed")]
    RouteMalformed,
    #[error("Route unknown")]
    RouteUnknown,
    #[error("Access to administrative route denied")]
    RouteDenied,
    #[error("access to zone not allowed")]
    ZoneDenied,
    #[error("Invalid request body")]
    InvalidRequestBody,
    #[error("Request Body not allowed")]
    RequestBodyDenied,
}

impl IntoResponse for Error {
    fn into_response(self) -> http::Response<axum::body::Body> {
        todo!()
    }
}

impl From<RouteError> for Error {
    fn from(value: RouteError) -> Self {
        match value {
            RouteError::Malformed => Self::RouteMalformed,
            RouteError::Unknown => Self::RouteUnknown,
        }
    }
}

impl From<Denied> for Error {
    fn from(value: Denied) -> Self {
        match value {
            Denied::Route => Self::RouteDenied,
            Denied::Zone => Self::ZoneDenied,
        }
    }
}

impl From<policy::BodyRejected> for Error {
    fn from(_err: policy::BodyRejected) -> Self {
        Self::RequestBodyDenied
    }
}
