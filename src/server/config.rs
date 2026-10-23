use axum::http;
use http::HeaderValue;
use http::header::InvalidHeaderValue;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error reading key from file {0}: {1}")]
    ReadingSpecifiedKey(PathBuf, std::io::Error),
    #[error("Both PDNS_API_KEY_FILE and PDNS_API_KEY set, please set only one")]
    DuplicatePdnsKeyGiven,
    #[error("Neither PDNS_API_KEY_FILE nor PDNS_API_KEY set")]
    NoKeyGiven,
    #[error("given PDNS key is empty")]
    EmptyKeyGiven,
    #[error("PDNS key can't be used as header: {0}")]
    InvalidPdnsKey(#[from] InvalidHeaderValue),
}
pub fn resolve_pdns_api_key(file: Option<PathBuf>) -> Result<http::HeaderValue, Error> {
    let env = std::env::var("PDNS_API_KEY").ok();

    let key = match (env, file) {
        (Some(api_key), None) => Ok(api_key),
        (None, Some(file_path)) => std::fs::read_to_string(&file_path)
            .map_err(|err| Error::ReadingSpecifiedKey(file_path, err)),
        (Some(_), Some(_)) => Err(Error::DuplicatePdnsKeyGiven),
        _ => Err(Error::NoKeyGiven),
    }?;

    let key = key.trim();

    // do basic validation of the key: non-empty and a valid header value
    if key.is_empty() {
        return Err(Error::EmptyKeyGiven);
    }
    let mut key = HeaderValue::from_str(key)?;
    key.set_sensitive(true);

    Ok(key)
}
