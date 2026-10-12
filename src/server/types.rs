use axum::body::Body;
use http::HeaderValue;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

pub type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct TawnyState {
    pub client: Client,
    pub pdns_api_key: HeaderValue,
}

impl TawnyState {
    pub fn new(pdns_api_key: HeaderValue) -> TawnyState {
        let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());

        Self {
            client,
            pdns_api_key,
        }
    }
}
