use axum::body::Body;
use http::{HeaderValue, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use jsonwebtoken::DecodingKey;

pub type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct TawnyState {
    pub client: Client,
    pub pdns_api_key: HeaderValue,
    pub public_key: DecodingKey,
    pub pdns_url: Uri,
}

impl TawnyState {
    pub fn new(pdns_api_key: HeaderValue, public_key: DecodingKey, pdns_url: Uri) -> TawnyState {
        let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

        Self {
            client,
            pdns_api_key,
            public_key,
            pdns_url,
        }
    }
}
