{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
  cfg = config.services.tawnydns;
in
{
  options.services.tawnydns = {
    enable = mkEnableOption "TawnyDNS";

    package = mkOption {
      type = types.package;
      default = pkgs.tawnydns;
      defaultText = lib.literalExpression "pkgs.tawnydns";
      description = "The TawnyDNS package to use.";
    };

    pdnsApiKeyFile = mkOption {
      type = types.path;
      description = "Path to a file containing the PowerDNS API key.";
      example = "/run/secrets/tawnydns-pdns-api-key";
    };

    publicKeyFile = mkOption {
      type = types.path;
      description = "Path to the public key used to verify the tenant tokens.";
      example = "/etc/tawnydns/tawnydns.pub";
    };

    listen = mkOption {
      type = types.str;
      default = "[::1]:8082";
      description = "Socket address to listen on.";
    };

    pdnsUrl = mkOption {
      type = types.str;
      default = "http://localhost:8081";
      description = "Base URL of the PowerDNS API (http only).";
    };

    logFilter = mkOption {
      type = types.str;
      default = "info";
      example = "info,tawnydns=debug";
      description = "Log filter, passed as RUST_LOG.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.tawnydns = {
      description = "TawnyDNS PowerDNS API proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} server";
        LoadCredential = [
          "pdns-api-key:${cfg.pdnsApiKeyFile}"
          "public-key:${cfg.publicKeyFile}"
        ];
        Restart = "on-failure";
        RestartSec = "10s";

        # Run as an ephemeral, systemd-managed user/group instead of a static one;
        # DynamicUser also implies NoNewPrivileges, ProtectSystem=strict,
        # ProtectHome=read-only, PrivateTmp and RemoveIPC.
        DynamicUser = true;

        # Security hardening
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      };

      environment = {
        PDNS_API_KEY_FILE = "%d/pdns-api-key";
        PUBLIC_KEY_FILE = "%d/public-key";
        LISTEN_ADDR = cfg.listen;
        PDNS_URL = cfg.pdnsUrl;
        RUST_LOG = cfg.logFilter;
      };
    };
  };
}
