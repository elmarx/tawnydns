use crate::policy::{BodyCheck, ResponseFilter};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    /// operation is never permitted for tokens
    #[error("route is never permitted for tenants")]
    Route,

    /// zone-scoped operation on a zone that is not part of the claim
    #[error("zone is not part of the token")]
    Zone,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Grant {
    /// `BodyCheck::apply` must accept the request body before it is forwarded
    pub body_condition: Option<BodyCheck>,
    /// the upstream response is passed through `ResponseFilter::apply`
    pub filter: Option<ResponseFilter>,
}
