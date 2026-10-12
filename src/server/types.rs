use axum::body::Body;
use http::{HeaderValue, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

pub type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct TawnyState {
    pub client: Client,
    pub pdns_api_key: HeaderValue,
    pub pdns_url: Uri,
}

impl TawnyState {
    pub fn new(pdns_api_key: HeaderValue) -> TawnyState {
        let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

        Self {
            client,
            pdns_api_key,
            pdns_url: "http://127.0.0.1:8081".parse().unwrap(),
        }
    }
}
