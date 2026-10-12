use eros::Context;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct Claim {
    #[serde(rename = "z")]
    pub zones: Vec<String>,
}

pub fn create(private_key_file: PathBuf, zone: String) -> eros::Result<String> {
    let claim = Claim { zones: vec![zone] };
    let header = Header::new(Algorithm::EdDSA);
    let key = std::fs::read_to_string(private_key_file).context("open private key file")?;
    let key = EncodingKey::from_ed_pem(key.as_bytes()).context("decode private key")?;

    let token = encode(&header, &claim, &key).context("encoying the token")?;

    Ok(token)
}

pub fn inspect(public_key_file: PathBuf, token: PathBuf) -> eros::Result<TokenData<Claim>> {
    let token = if token == *"-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("read token from stdin")?;
        input
    } else {
        std::fs::read_to_string(token).context("read token from disk")?
    };
    let decoding_key = std::fs::read_to_string(public_key_file).context("open public key file")?;
    let decoding_key =
        DecodingKey::from_ed_pem(decoding_key.as_bytes()).context("decode public key")?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();

    let token =
        decode::<Claim>(token.trim(), &decoding_key, &validation).context("decoding token")?;

    Ok(token)
}
