//! Request body checks, run once the body is buffered, and before it is forwarded. A failure denies the request.
use crate::token::Claim;
use bytes::Bytes;

/// the request body asks for something the claim does not permit
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Body not allowed for given token")]
pub struct BodyRejected;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BodyCheck {
    CreateZone,
    PutZone,
}

impl BodyCheck {
    /// Checks a request body, to be called once the body is buffered.
    pub fn apply(self, _claim: &Claim, _body: &Bytes) -> Result<(), BodyRejected> {
        match self {
            BodyCheck::CreateZone => todo!("name is a zone of the claim, only allowed fields"),
            BodyCheck::PutZone => todo!("no kind/masters changes"),
        }
    }
}
