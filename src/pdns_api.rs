use http::Method;
use percent_encoding::percent_decode_str;

/// One variant per operation of the PowerDNS authoritative API (method + path),
/// path parameters are percent-decoded.
#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(test), expect(dead_code))]
pub enum Route {
    /// `GET /api/v1/servers`
    ListServers,
    /// `GET /api/v1/servers/{server}`
    GetServer { server: String },
    /// `GET /api/v1/servers/{server}/autoprimaries`
    ListAutoprimaries { server: String },
    /// `POST /api/v1/servers/{server}/autoprimaries`
    CreateAutoprimary { server: String },
    /// `DELETE /api/v1/servers/{server}/autoprimaries/{ip}/{nameserver}`
    DeleteAutoprimary {
        server: String,
        ip: String,
        nameserver: String,
    },
    /// `PUT /api/v1/servers/{server}/cache/flush`
    FlushCache { server: String },
    /// `GET /api/v1/servers/{server}/config`
    GetConfig { server: String },
    /// `GET /api/v1/servers/{server}/networks`
    ListNetworks { server: String },
    /// `GET /api/v1/servers/{server}/networks/{ip}/{prefixlen}`
    GetNetwork {
        server: String,
        ip: String,
        prefixlen: String,
    },
    /// `PUT /api/v1/servers/{server}/networks/{ip}/{prefixlen}`
    SetNetwork {
        server: String,
        ip: String,
        prefixlen: String,
    },
    /// `GET /api/v1/servers/{server}/search-data`
    SearchData { server: String },
    /// `GET /api/v1/servers/{server}/statistics`
    GetStatistics { server: String },
    /// `GET /api/v1/servers/{server}/tsigkeys`
    ListTsigKeys { server: String },
    /// `POST /api/v1/servers/{server}/tsigkeys`
    CreateTsigKey { server: String },
    /// `GET /api/v1/servers/{server}/tsigkeys/{tsigkey}`
    GetTsigKey { server: String, tsigkey: String },
    /// `PUT /api/v1/servers/{server}/tsigkeys/{tsigkey}`
    PutTsigKey { server: String, tsigkey: String },
    /// `DELETE /api/v1/servers/{server}/tsigkeys/{tsigkey}`
    DeleteTsigKey { server: String, tsigkey: String },
    /// `GET /api/v1/servers/{server}/views`
    ListViews { server: String },
    /// `GET /api/v1/servers/{server}/views/{view}`
    ListView { server: String, view: String },
    /// `POST /api/v1/servers/{server}/views/{view}`
    AddToView { server: String, view: String },
    /// `DELETE /api/v1/servers/{server}/views/{view}/{id}`
    DeleteFromView {
        server: String,
        view: String,
        id: String,
    },
    /// `GET /api/v1/servers/{server}/zones`
    ListZones { server: String },
    /// `POST /api/v1/servers/{server}/zones`
    CreateZone { server: String },
    /// `GET /api/v1/servers/{server}/zones/{zone}`
    GetZone { server: String, zone: String },
    /// `PATCH /api/v1/servers/{server}/zones/{zone}`
    PatchZone { server: String, zone: String },
    /// `PUT /api/v1/servers/{server}/zones/{zone}`
    PutZone { server: String, zone: String },
    /// `DELETE /api/v1/servers/{server}/zones/{zone}`
    DeleteZone { server: String, zone: String },
    /// `PUT /api/v1/servers/{server}/zones/{zone}/axfr-retrieve`
    AxfrRetrieve { server: String, zone: String },
    /// `GET /api/v1/servers/{server}/zones/{zone}/cryptokeys`
    ListCryptokeys { server: String, zone: String },
    /// `POST /api/v1/servers/{server}/zones/{zone}/cryptokeys`
    CreateCryptokey { server: String, zone: String },
    /// `GET /api/v1/servers/{server}/zones/{zone}/cryptokeys/{cryptokey}`
    GetCryptokey {
        server: String,
        zone: String,
        cryptokey: String,
    },
    /// `PUT /api/v1/servers/{server}/zones/{zone}/cryptokeys/{cryptokey}`
    ModifyCryptokey {
        server: String,
        zone: String,
        cryptokey: String,
    },
    /// `DELETE /api/v1/servers/{server}/zones/{zone}/cryptokeys/{cryptokey}`
    DeleteCryptokey {
        server: String,
        zone: String,
        cryptokey: String,
    },
    /// `GET /api/v1/servers/{server}/zones/{zone}/export`
    ExportZone { server: String, zone: String },
    /// `GET /api/v1/servers/{server}/zones/{zone}/metadata`
    ListMetadata { server: String, zone: String },
    /// `POST /api/v1/servers/{server}/zones/{zone}/metadata`
    CreateMetadata { server: String, zone: String },
    /// `GET /api/v1/servers/{server}/zones/{zone}/metadata/{kind}`
    GetMetadata {
        server: String,
        zone: String,
        kind: String,
    },
    /// `PUT /api/v1/servers/{server}/zones/{zone}/metadata/{kind}`
    ModifyMetadata {
        server: String,
        zone: String,
        kind: String,
    },
    /// `DELETE /api/v1/servers/{server}/zones/{zone}/metadata/{kind}`
    DeleteMetadata {
        server: String,
        zone: String,
        kind: String,
    },
    /// `PUT /api/v1/servers/{server}/zones/{zone}/notify`
    NotifyZone { server: String, zone: String },
    /// `PUT /api/v1/servers/{server}/zones/{zone}/rectify`
    RectifyZone { server: String, zone: String },
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(not(test), expect(dead_code))]
pub enum RouteError {
    /// well-formed request, but not an operation we know (config, search, tsigkeys, ...)
    Unknown,
    /// hostile or invalid path (dot segments, bad encoding, ...)
    Malformed,
}

impl Route {
    #[expect(dead_code)]
    /// The zone addressed by the path, if any (`CreateZone` has none: the zone is in the body).
    pub fn zone(&self) -> Option<&str> {
        match self {
            Route::GetZone { zone, .. }
            | Route::PatchZone { zone, .. }
            | Route::PutZone { zone, .. }
            | Route::DeleteZone { zone, .. }
            | Route::AxfrRetrieve { zone, .. }
            | Route::ExportZone { zone, .. }
            | Route::NotifyZone { zone, .. }
            | Route::RectifyZone { zone, .. }
            | Route::ListCryptokeys { zone, .. }
            | Route::CreateCryptokey { zone, .. }
            | Route::GetCryptokey { zone, .. }
            | Route::ModifyCryptokey { zone, .. }
            | Route::DeleteCryptokey { zone, .. }
            | Route::ListMetadata { zone, .. }
            | Route::CreateMetadata { zone, .. }
            | Route::GetMetadata { zone, .. }
            | Route::ModifyMetadata { zone, .. }
            | Route::DeleteMetadata { zone, .. } => Some(zone),
            // a zone rule on a route without a zone is denied, so a missed route fails closed
            _ => None,
        }
    }
}

impl TryFrom<(&Method, &str)> for Route {
    type Error = RouteError;

    #[allow(
        clippy::too_many_lines,
        reason = "one flat match arm per API operation"
    )]
    fn try_from((method, path): (&Method, &str)) -> Result<Self, Self::Error> {
        let Some(rest) = path.strip_prefix("/api/v1/servers") else {
            return Err(RouteError::Unknown);
        };

        let raw: Vec<&str> = match rest {
            "" => Vec::new(),
            _ => rest
                .strip_prefix('/')
                .ok_or(RouteError::Unknown)?
                .split('/')
                .collect(),
        };

        let decoded = raw
            .into_iter()
            .map(decode_segment)
            .collect::<Result<Vec<_>, _>>()?;
        let segments = decoded.iter().map(String::as_str).collect::<Vec<_>>();

        let route = match (method, segments.as_slice()) {
            (&Method::GET, []) => Route::ListServers,
            (&Method::GET, [server]) => Route::GetServer {
                server: server.to_string(),
            },

            (&Method::GET, [server, "autoprimaries"]) => Route::ListAutoprimaries {
                server: server.to_string(),
            },
            (&Method::POST, [server, "autoprimaries"]) => Route::CreateAutoprimary {
                server: server.to_string(),
            },
            (&Method::DELETE, [server, "autoprimaries", ip, nameserver]) => {
                Route::DeleteAutoprimary {
                    server: server.to_string(),
                    ip: ip.to_string(),
                    nameserver: nameserver.to_string(),
                }
            }

            (&Method::PUT, [server, "cache", "flush"]) => Route::FlushCache {
                server: server.to_string(),
            },
            (&Method::GET, [server, "config"]) => Route::GetConfig {
                server: server.to_string(),
            },

            (&Method::GET, [server, "networks"]) => Route::ListNetworks {
                server: server.to_string(),
            },
            (&Method::GET, [server, "networks", ip, prefixlen]) => Route::GetNetwork {
                server: server.to_string(),
                ip: ip.to_string(),
                prefixlen: prefixlen.to_string(),
            },
            (&Method::PUT, [server, "networks", ip, prefixlen]) => Route::SetNetwork {
                server: server.to_string(),
                ip: ip.to_string(),
                prefixlen: prefixlen.to_string(),
            },

            (&Method::GET, [server, "search-data"]) => Route::SearchData {
                server: server.to_string(),
            },
            (&Method::GET, [server, "statistics"]) => Route::GetStatistics {
                server: server.to_string(),
            },

            (&Method::GET, [server, "tsigkeys"]) => Route::ListTsigKeys {
                server: server.to_string(),
            },
            (&Method::POST, [server, "tsigkeys"]) => Route::CreateTsigKey {
                server: server.to_string(),
            },
            (&Method::GET, [server, "tsigkeys", tsigkey]) => Route::GetTsigKey {
                server: server.to_string(),
                tsigkey: tsigkey.to_string(),
            },
            (&Method::PUT, [server, "tsigkeys", tsigkey]) => Route::PutTsigKey {
                server: server.to_string(),
                tsigkey: tsigkey.to_string(),
            },
            (&Method::DELETE, [server, "tsigkeys", tsigkey]) => Route::DeleteTsigKey {
                server: server.to_string(),
                tsigkey: tsigkey.to_string(),
            },

            (&Method::GET, [server, "views"]) => Route::ListViews {
                server: server.to_string(),
            },
            (&Method::GET, [server, "views", view]) => Route::ListView {
                server: server.to_string(),
                view: view.to_string(),
            },
            (&Method::POST, [server, "views", view]) => Route::AddToView {
                server: server.to_string(),
                view: view.to_string(),
            },
            (&Method::DELETE, [server, "views", view, id]) => Route::DeleteFromView {
                server: server.to_string(),
                view: view.to_string(),
                id: id.to_string(),
            },

            (&Method::GET, [server, "zones"]) => Route::ListZones {
                server: server.to_string(),
            },
            (&Method::POST, [server, "zones"]) => Route::CreateZone {
                server: server.to_string(),
            },
            (&Method::GET, [server, "zones", zone]) => Route::GetZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::PATCH, [server, "zones", zone]) => Route::PatchZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::PUT, [server, "zones", zone]) => Route::PutZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::DELETE, [server, "zones", zone]) => Route::DeleteZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },

            (&Method::PUT, [server, "zones", zone, "axfr-retrieve"]) => Route::AxfrRetrieve {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::GET, [server, "zones", zone, "export"]) => Route::ExportZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::PUT, [server, "zones", zone, "notify"]) => Route::NotifyZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::PUT, [server, "zones", zone, "rectify"]) => Route::RectifyZone {
                server: server.to_string(),
                zone: zone.to_string(),
            },

            (&Method::GET, [server, "zones", zone, "cryptokeys"]) => Route::ListCryptokeys {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::POST, [server, "zones", zone, "cryptokeys"]) => Route::CreateCryptokey {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::GET, [server, "zones", zone, "cryptokeys", cryptokey]) => {
                Route::GetCryptokey {
                    server: server.to_string(),
                    zone: zone.to_string(),
                    cryptokey: cryptokey.to_string(),
                }
            }
            (&Method::PUT, [server, "zones", zone, "cryptokeys", cryptokey]) => {
                Route::ModifyCryptokey {
                    server: server.to_string(),
                    zone: zone.to_string(),
                    cryptokey: cryptokey.to_string(),
                }
            }
            (&Method::DELETE, [server, "zones", zone, "cryptokeys", cryptokey]) => {
                Route::DeleteCryptokey {
                    server: server.to_string(),
                    zone: zone.to_string(),
                    cryptokey: cryptokey.to_string(),
                }
            }

            (&Method::GET, [server, "zones", zone, "metadata"]) => Route::ListMetadata {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::POST, [server, "zones", zone, "metadata"]) => Route::CreateMetadata {
                server: server.to_string(),
                zone: zone.to_string(),
            },
            (&Method::GET, [server, "zones", zone, "metadata", kind]) => Route::GetMetadata {
                server: server.to_string(),
                zone: zone.to_string(),
                kind: kind.to_string(),
            },
            (&Method::PUT, [server, "zones", zone, "metadata", kind]) => Route::ModifyMetadata {
                server: server.to_string(),
                zone: zone.to_string(),
                kind: kind.to_string(),
            },
            (&Method::DELETE, [server, "zones", zone, "metadata", kind]) => Route::DeleteMetadata {
                server: server.to_string(),
                zone: zone.to_string(),
                kind: kind.to_string(),
            },

            _ => return Err(RouteError::Unknown),
        };

        Ok(route)
    }
}

/// Percent-decodes one raw path segment and rejects anything that could be used to
/// smuggle paths or confuse downstream components.
#[cfg_attr(not(test), expect(dead_code))]
fn decode_segment(raw: &str) -> Result<String, RouteError> {
    if raw.is_empty() {
        return Err(RouteError::Malformed);
    }

    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| RouteError::Malformed)?;

    let hostile = decoded == "."
        || decoded == ".."
        || decoded
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == '/');
    if hostile {
        return Err(RouteError::Malformed);
    }

    Ok(decoded.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn parse(method: &Method, path: &str) -> Result<Route, RouteError> {
        Route::try_from((method, path))
    }

    /// one test per operation: `name: METHOD "path" => expected route`
    macro_rules! recognizes {
        ($($name:ident: $method:ident $path:literal => $expected:expr;)*) => {
            $(
                #[test]
                fn $name() {
                    let actual = parse(&Method::$method, $path);
                    assert_eq!(actual, Ok($expected));
                }
            )*
        };
    }

    recognizes! {
        list_servers: GET "/api/v1/servers" => Route::ListServers;
        get_server: GET "/api/v1/servers/localhost" => Route::GetServer { server: s("localhost") };

        list_autoprimaries: GET "/api/v1/servers/localhost/autoprimaries" => Route::ListAutoprimaries { server: s("localhost") };
        create_autoprimary: POST "/api/v1/servers/localhost/autoprimaries" => Route::CreateAutoprimary { server: s("localhost") };
        delete_autoprimary: DELETE "/api/v1/servers/localhost/autoprimaries/192.0.2.1/ns1.example.com" => Route::DeleteAutoprimary {
            server: s("localhost"),
            ip: s("192.0.2.1"),
            nameserver: s("ns1.example.com"),
        };

        flush_cache: PUT "/api/v1/servers/localhost/cache/flush" => Route::FlushCache { server: s("localhost") };
        get_config: GET "/api/v1/servers/localhost/config" => Route::GetConfig { server: s("localhost") };

        list_networks: GET "/api/v1/servers/localhost/networks" => Route::ListNetworks { server: s("localhost") };
        get_network: GET "/api/v1/servers/localhost/networks/192.0.2.0/24" => Route::GetNetwork {
            server: s("localhost"),
            ip: s("192.0.2.0"),
            prefixlen: s("24"),
        };
        set_network: PUT "/api/v1/servers/localhost/networks/192.0.2.0/24" => Route::SetNetwork {
            server: s("localhost"),
            ip: s("192.0.2.0"),
            prefixlen: s("24"),
        };

        search_data: GET "/api/v1/servers/localhost/search-data" => Route::SearchData { server: s("localhost") };
        get_statistics: GET "/api/v1/servers/localhost/statistics" => Route::GetStatistics { server: s("localhost") };

        list_tsig_keys: GET "/api/v1/servers/localhost/tsigkeys" => Route::ListTsigKeys { server: s("localhost") };
        create_tsig_key: POST "/api/v1/servers/localhost/tsigkeys" => Route::CreateTsigKey { server: s("localhost") };
        get_tsig_key: GET "/api/v1/servers/localhost/tsigkeys/key1" => Route::GetTsigKey { server: s("localhost"), tsigkey: s("key1") };
        put_tsig_key: PUT "/api/v1/servers/localhost/tsigkeys/key1" => Route::PutTsigKey { server: s("localhost"), tsigkey: s("key1") };
        delete_tsig_key: DELETE "/api/v1/servers/localhost/tsigkeys/key1" => Route::DeleteTsigKey { server: s("localhost"), tsigkey: s("key1") };

        list_views: GET "/api/v1/servers/localhost/views" => Route::ListViews { server: s("localhost") };
        list_view: GET "/api/v1/servers/localhost/views/internal" => Route::ListView { server: s("localhost"), view: s("internal") };
        add_to_view: POST "/api/v1/servers/localhost/views/internal" => Route::AddToView { server: s("localhost"), view: s("internal") };
        delete_from_view: DELETE "/api/v1/servers/localhost/views/internal/example.com.." => Route::DeleteFromView {
            server: s("localhost"),
            view: s("internal"),
            id: s("example.com.."),
        };

        list_zones: GET "/api/v1/servers/localhost/zones" => Route::ListZones { server: s("localhost") };
        create_zone: POST "/api/v1/servers/localhost/zones" => Route::CreateZone { server: s("localhost") };
        get_zone: GET "/api/v1/servers/localhost/zones/example.com." => Route::GetZone { server: s("localhost"), zone: s("example.com.") };
        patch_zone: PATCH "/api/v1/servers/localhost/zones/example.com." => Route::PatchZone { server: s("localhost"), zone: s("example.com.") };
        put_zone: PUT "/api/v1/servers/localhost/zones/example.com." => Route::PutZone { server: s("localhost"), zone: s("example.com.") };
        delete_zone: DELETE "/api/v1/servers/localhost/zones/example.com." => Route::DeleteZone { server: s("localhost"), zone: s("example.com.") };

        axfr_retrieve: PUT "/api/v1/servers/localhost/zones/example.com./axfr-retrieve" => Route::AxfrRetrieve { server: s("localhost"), zone: s("example.com.") };
        export_zone: GET "/api/v1/servers/localhost/zones/example.com./export" => Route::ExportZone { server: s("localhost"), zone: s("example.com.") };
        notify_zone: PUT "/api/v1/servers/localhost/zones/example.com./notify" => Route::NotifyZone { server: s("localhost"), zone: s("example.com.") };
        rectify_zone: PUT "/api/v1/servers/localhost/zones/example.com./rectify" => Route::RectifyZone { server: s("localhost"), zone: s("example.com.") };

        list_cryptokeys: GET "/api/v1/servers/localhost/zones/example.com./cryptokeys" => Route::ListCryptokeys { server: s("localhost"), zone: s("example.com.") };
        create_cryptokey: POST "/api/v1/servers/localhost/zones/example.com./cryptokeys" => Route::CreateCryptokey { server: s("localhost"), zone: s("example.com.") };
        get_cryptokey: GET "/api/v1/servers/localhost/zones/example.com./cryptokeys/1" => Route::GetCryptokey {
            server: s("localhost"),
            zone: s("example.com."),
            cryptokey: s("1"),
        };
        modify_cryptokey: PUT "/api/v1/servers/localhost/zones/example.com./cryptokeys/1" => Route::ModifyCryptokey {
            server: s("localhost"),
            zone: s("example.com."),
            cryptokey: s("1"),
        };
        delete_cryptokey: DELETE "/api/v1/servers/localhost/zones/example.com./cryptokeys/1" => Route::DeleteCryptokey {
            server: s("localhost"),
            zone: s("example.com."),
            cryptokey: s("1"),
        };

        list_metadata: GET "/api/v1/servers/localhost/zones/example.com./metadata" => Route::ListMetadata { server: s("localhost"), zone: s("example.com.") };
        create_metadata: POST "/api/v1/servers/localhost/zones/example.com./metadata" => Route::CreateMetadata { server: s("localhost"), zone: s("example.com.") };
        get_metadata: GET "/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY" => Route::GetMetadata {
            server: s("localhost"),
            zone: s("example.com."),
            kind: s("ALSO-NOTIFY"),
        };
        modify_metadata: PUT "/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY" => Route::ModifyMetadata {
            server: s("localhost"),
            zone: s("example.com."),
            kind: s("ALSO-NOTIFY"),
        };
        delete_metadata: DELETE "/api/v1/servers/localhost/zones/example.com./metadata/ALSO-NOTIFY" => Route::DeleteMetadata {
            server: s("localhost"),
            zone: s("example.com."),
            kind: s("ALSO-NOTIFY"),
        };
    }

    #[test]
    fn a_wrong_method_is_unknown() {
        let samples = [
            (Method::POST, "/api/v1/servers"),
            (
                Method::GET,
                "/api/v1/servers/localhost/zones/example.com./notify",
            ),
            (
                Method::POST,
                "/api/v1/servers/localhost/zones/example.com./export",
            ),
            (Method::DELETE, "/api/v1/servers/localhost"),
        ];
        for (method, path) in samples {
            let actual = parse(&method, path);
            assert_eq!(actual, Err(RouteError::Unknown), "{method} {path}");
        }
    }

    #[test]
    fn unsupported_paths_are_unknown() {
        let samples = [
            "/",
            "/api",
            "/api/v1",
            "/api/v2/servers",
            "/api/v1/server",
            "/api/v1/serversfoo",
            "/api/v1/servers/localhost/unknown",
            "/api/v1/servers/localhost/zones/example.com./unknown",
            "/api/v1/servers/localhost/cache/flush/more",
            "/api/v1/servers/localhost/zones/example.com./export/more",
            "/healthz",
        ];
        for sample in samples {
            let actual = parse(&Method::GET, sample);
            assert_eq!(actual, Err(RouteError::Unknown), "{sample}");
        }
    }

    #[test]
    fn segments_are_percent_decoded() {
        let actual = parse(
            &Method::GET,
            "/api/v1/servers/local%68ost/zones/example%2Ecom.",
        );
        let expected = Route::GetZone {
            server: s("localhost"),
            zone: s("example.com."),
        };
        assert_eq!(actual, Ok(expected));
    }

    #[test]
    fn an_encoded_slash_is_malformed() {
        let samples = [
            "/api/v1/servers/localhost/zones/a%2Fb",
            "/api/v1/servers/localhost/zones/a%2fb",
            "/api/v1/servers/loc%2Falhost/zones",
            "/api/v1/servers/localhost/zones/example.com.%2Fexport",
        ];
        for sample in samples {
            let actual = parse(&Method::GET, sample);
            assert_eq!(actual, Err(RouteError::Malformed), "{sample}");
        }
    }

    #[test]
    fn hostile_paths_are_malformed() {
        let samples = [
            // empty segments
            "/api/v1/servers/",
            "/api/v1/servers//zones",
            "/api/v1/servers/localhost/zones/",
            "/api/v1/servers/localhost//zones/example.com.",
            // dot segments, plain and encoded
            "/api/v1/servers/localhost/zones/.",
            "/api/v1/servers/localhost/zones/..",
            "/api/v1/servers/localhost/zones/%2e",
            "/api/v1/servers/localhost/zones/%2E%2E",
            "/api/v1/servers/localhost/zones/.%2e",
            "/api/v1/servers/../zones",
            // NUL and control characters
            "/api/v1/servers/localhost/zones/example.com.%00",
            "/api/v1/servers/localhost/zones/a%0Ab",
            "/api/v1/servers/localhost/zones/a%0Db",
            "/api/v1/servers/localhost/zones/a%7Fb",
            // backslash
            "/api/v1/servers/localhost/zones/a%5Cb",
            // invalid UTF-8
            "/api/v1/servers/localhost/zones/%ff",
            "/api/v1/servers/localhost/zones/%c0%af",
        ];
        for sample in samples {
            let actual = parse(&Method::GET, sample);
            assert_eq!(actual, Err(RouteError::Malformed), "{sample}");
        }
    }

    #[test]
    fn a_dot_inside_a_segment_is_fine() {
        let actual = parse(
            &Method::GET,
            "/api/v1/servers/localhost/zones/..example.com.",
        );
        let expected = Route::GetZone {
            server: s("localhost"),
            zone: s("..example.com."),
        };
        assert_eq!(actual, Ok(expected));
    }

    #[test]
    fn pdns_escapes_are_kept_verbatim() {
        let actual = parse(
            &Method::GET,
            "/api/v1/servers/localhost/zones/1.0.10.in-addr.arpa.=2F24",
        );
        let expected = Route::GetZone {
            server: s("localhost"),
            zone: s("1.0.10.in-addr.arpa.=2F24"),
        };
        assert_eq!(actual, Ok(expected));
    }
}
