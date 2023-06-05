use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::env::VarError;
use std::fs::File;
use std::io::BufReader;
use thiserror::Error;

#[derive(Deserialize, Debug)]
struct Zone {
    name: String,
    key: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("cannot read environment variable {0:?}")]
    VarError(#[from] VarError),

    #[error("cannot read config-file: {0:?}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse config-file: {0:?}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub key_to_zone: HashMap<String, String>,
    pub api_key: String,
}

pub fn read_config() -> Result<Config, ConfigError> {
    let config_file = env::var("PPD_ZONE_FILE")?;
    let api_key = env::var("PPD_X_API_KEY")?;

    let file = File::open(config_file)?;
    let reader = BufReader::new(file);

    let zones: Vec<Zone> = serde_json::from_reader(reader)?;

    Ok(Config {
        key_to_zone: zones.into_iter().map(|z| (z.key, z.name)).collect(),
        api_key,
    })
}
