use super::Error;
use super::model::{PatchZone, Zone};

pub trait ApiClient: Clone + Send + Sync + 'static {
    async fn get_zone(&self, zone: &str) -> Result<Zone, Error>;
    async fn patch_zone(&self, zone: &str, payload: &PatchZone) -> Result<(), Error>;
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    api_key: String,
    pdns_server_url: String,
}

impl Client {
    pub fn new(pdns_server_url: String, api_key: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            pdns_server_url,
        }
    }

    fn zone_endpoint(&self, zone: &str) -> String {
        format!(
            "{}/api/v1/servers/localhost/zones/{zone}.",
            self.pdns_server_url
        )
    }
}

impl ApiClient for Client {
    async fn get_zone(&self, zone: &str) -> Result<Zone, Error> {
        Ok(self
            .http
            .get(self.zone_endpoint(zone))
            .header("X-API-Key", &self.api_key)
            .send()
            .await?
            .error_for_status()?
            .json::<Zone>()
            .await?)
    }

    async fn patch_zone(&self, zone: &str, payload: &PatchZone) -> Result<(), Error> {
        self.http
            .patch(self.zone_endpoint(zone))
            .json(payload)
            .header("X-API-Key", &self.api_key)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_endpoint_uses_base_url_and_requested_zone() {
        let client = Client::new("http://localhost:8081".into(), "key".into());

        assert_eq!(
            client.zone_endpoint("example"),
            "http://localhost:8081/api/v1/servers/localhost/zones/example."
        );
    }
}
