# https://just.systems

ci:
    cargo check --all-targets
    cargo fmt --check
    cargo clippy --all-targets -- -W clippy::pedantic
    cargo nextest run

mitmproxy:
  mitmweb --mode reverse:http://localhost:4000 --web-port 8181 --listen-port 4001
