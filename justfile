# https://just.systems

ci:
    cargo check --all-targets
    cargo fmt --check
    cargo clippy --all-targets -- -W clippy::pedantic
    # cargo nextest run

generate_pdns_client:
  jj new -m "regenerate pdns client"
  curl -sfS --output-dir=pdns -OJ https://raw.githubusercontent.com/PowerDNS/pdns/refs/heads/master/docs/http-api/openapi/authoritative-api-openapi.yaml
  openapi-to-rust generate --config openapi-to-rust.toml
  awk '/^\[dependencies\]/{exit} {print}' pdns/Cargo.toml > pdns/Cargo.temp.toml
  cat pdns/src/generated/REQUIRED_DEPS.toml >> pdns/Cargo.temp.toml
  mv pdns/Cargo.{temp.,}toml
  cargo clippy --allow-dirty --fix --quiet --lib -p pdns -- -W clippy::pedantic --no-deps &> /dev/null
  # clippy fix needs a second run to fix all lints
  cargo clippy --allow-dirty --fix --quiet --lib -p pdns -- -W clippy::pedantic --no-deps &> /dev/null
  cargo fmt -p pdns
