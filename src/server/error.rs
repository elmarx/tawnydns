use crate::pdns::RouteError;
use crate::policy;
use crate::policy::{Denied, FilterError};
use axum::body::Body;
use axum::response::IntoResponse;
use http::{Response, StatusCode, header};

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
    #[error("Operation not permitted by the token")]
    PermissionDenied,
    #[error("Invalid request body")]
    InvalidRequestBody,
    #[error("Request body too large")]
    RequestBodyTooLarge,
    #[error("Request Body not allowed")]
    RequestBodyDenied,
    #[error("Invalid content type, only json is supported")]
    InvalidContentType,
    #[error("Upstream response could not be read")]
    UpstreamBody(#[source] axum::Error),
    #[error("Upstream response could not be filtered")]
    UpstreamFilter(#[from] FilterError),
}

impl Error {
    /// Maps a failure of buffering the request body: reaching the size limit is a 413,
    /// anything else (e.g. client disconnect) a 400 that is logged.
    pub fn from_request_body(err: &axum::Error) -> Self {
        use std::error::Error as _;

        if err
            .source()
            .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>)
        {
            Self::RequestBodyTooLarge
        } else {
            tracing::debug!("failed to read request body: {err:?}");
            Self::InvalidRequestBody
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::RouteMalformed | Self::InvalidRequestBody => StatusCode::BAD


            _REQUEST,
            Self::RouteUnknown => StatusCode::NOT_FOUND,
            Self::RouteDenied
            | Self::ZoneDenied
            | Self::PermissionDenied
            | Self::RequestBodyDenied => StatusCode::FORBIDDEN,
            Self::RequestBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::UpstreamBody(_) | Self::UpstreamFilter(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response<Body> {
        let status = self.status();
        if status.is_server_error() {
            // the source error is only logged, the client gets the generic display message
            tracing::warn!("failed to handle request: {self:?}");
        }

        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "error": self.to_string() }).to_string(),
            ))
            .unwrap()
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
            Denied::Permission => Self::PermissionDenied,
        }
    }
}

impl From<crate::content_type::Error> for Error {
    fn from(_err: crate::content_type::Error) -> Self {
        Self::InvalidContentType
    }
}

impl From<policy::BodyError> for Error {
    fn from(err: policy::BodyError) -> Self {
        match err {
            policy::BodyError::BodyRejected => Self::RequestBodyDenied,
            policy::BodyError::InvalidBody => Self::InvalidRequestBody,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream_body_error() -> Error {
        Error::UpstreamBody(axum::Error::new("boom"))
    }

    #[test]
    fn maps_errors_to_status() {
        let samples = [
            (Error::RouteMalformed, StatusCode::BAD_REQUEST),
            (Error::InvalidRequestBody, StatusCode::BAD_REQUEST),
            (Error::RouteUnknown, StatusCode::NOT_FOUND),
            (Error::RouteDenied, StatusCode::FORBIDDEN),
            (Error::ZoneDenied, StatusCode::FORBIDDEN),
            (Error::PermissionDenied, StatusCode::FORBIDDEN),
            (Error::RequestBodyDenied, StatusCode::FORBIDDEN),
            (Error::RequestBodyTooLarge, StatusCode::PAYLOAD_TOO_LARGE),
            (
                Error::InvalidContentType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (upstream_body_error(), StatusCode::BAD_GATEWAY),
            (
                Error::UpstreamFilter(FilterError::Json(
                    serde_json::from_str::<()>("x").unwrap_err(),
                )),
                StatusCode::BAD_GATEWAY,
            ),
        ];

        for (sample, expected) in samples {
            let actual = sample.into_response();

            assert_eq!(actual.status(), expected);
        }
    }

    #[tokio::test]
    async fn body_over_the_limit_is_too_large() {
        let sample = axum::body::Body::from(vec![0u8; 16]);

        let actual = axum::body::to_bytes(sample, 8).await.unwrap_err();

        let actual = Error::from_request_body(&actual);
        assert!(matches!(actual, Error::RequestBodyTooLarge), "{actual:?}");
    }

    #[tokio::test]
    async fn responds_with_json_error_without_leaking_the_source() {
        let sample = upstream_body_error();

        let actual = sample.into_response();

        assert_eq!(
            actual.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let actual = axum::body::to_bytes(actual.into_body(), usize::MAX)
            .await
            .unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&actual).unwrap();
        let expected = serde_json::json!({ "error": "Upstream response could not be read" });
        assert_eq!(actual, expected);
    }
}
