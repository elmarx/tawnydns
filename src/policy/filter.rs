//! Response filters: remove what the claim doesn't cover from a pdns response to an allowed request.
use crate::token::Claim;

#[expect(dead_code)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseFilter {
    ZoneList,
}

#[expect(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("response is not valid JSON")]
    Json(#[from] serde_json::Error),
}

#[expect(dead_code)]
impl ResponseFilter {
    /// Filters a response body, to be called once the body is buffered.
    pub fn apply(self, _claim: &Claim, _body: &bytes::Bytes) -> Result<bytes::Bytes, FilterError> {
        todo!()
    }
}
