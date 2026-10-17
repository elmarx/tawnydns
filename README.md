# tawnydns — the tenant-addon for PowerDNS

A multi-tenancy proxy for the [PowerDNS Authoritative HTTP API](https://doc.powerdns.com/authoritative/http-api/).

## Motivation

The PowerDNS API supports only a single API key, which grants access to everything. Out of the box, there is no way to restrict access to certain zones.

tawnydns adds support for tenants.

## Overview

tawnydns sits in front of the PowerDNS API and is transparent to clients. It accepts the `X-API-Key` header, but instead of a single API key, each tenant gets its own. If the tenant is authorized, tawnydns replaces the key with the real one.

Tenant API keys are JWTs that list the zones the tenant is authorized for.

For every request, tawnydns:

1. verifies the API key (JWT), so no state is required
2. checks that the zone in the request is one the token allows
3. inspects request bodies where needed, e.g. a tenant may create a zone it owns but not change its `kind` or `masters`
4. forwards the permitted request to PowerDNS using the real API key
5. filters responses where needed, e.g. the zone list contains only the tenant's own zones

tawnydns denies everything else (403). This includes all server-wide endpoints, such as TSIG keys, cryptokeys, metadata, config and search. Requests that carry the real PowerDNS API key are passed through unchanged, so admins can use the same endpoint.

## Usage

Run `tawnydns --help` for all commands and options. Logging is configured via the usual [`RUST_LOG` environment variable](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives), e.g. `RUST_LOG=info,tawnydns=debug`.

### Tokens

Create a key pair: the server verifies tokens with the public key, and you sign a token per tenant with the private key.

```bash
tawnydns keygen                     # writes private.key and tawnydns.pub
tawnydns token create example.com   # prints a token for example.com
```

### Server

See `tawnydns server --help` for all options.

```bash
export PDNS_API_KEY=secret          # or PDNS_API_KEY_FILE=/path/to/key
export PUBLIC_KEY_FILE=tawnydns.pub
tawnydns server --listen '[::1]:8082' --pdns-url http://localhost:8081
```

#### PowerDNS configuration

Enable the [API](https://doc.powerdns.com/authoritative/settings.html#setting-api) and set an [API key](https://doc.powerdns.com/authoritative/settings.html#setting-api-key) in `pdns.conf`. tawnydns uses the same key (`PDNS_API_KEY`):

```ini
api=yes
api-key=secret
```

The API listens on `127.0.0.1:8081` by default ([`webserver-address`](https://doc.powerdns.com/authoritative/settings.html#setting-webserver-address), [`webserver-port`](https://doc.powerdns.com/authoritative/settings.html#setting-webserver-port)). Keep it reachable only by tawnydns, so tenants can't bypass it.
