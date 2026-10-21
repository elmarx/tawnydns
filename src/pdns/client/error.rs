#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to send request to powerdns: {0}")]
    RequestError(#[from] reqwest::Error),
}
