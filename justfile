# https://just.systems

ci: 
    cargo check --all-targets
    cargo fmt --check
    cargo clippy --all-targets
    cargo clippy --all-targets -- -D clippy::pedantic
    cargo nextest run

clippy:
    cargo fmt --check
    cargo clippy --all-targets -- -W clippy::pedantic

mitmproxy:
  mitmweb --mode reverse:http://localhost:8082 --web-port 8181 --listen-port 4001
