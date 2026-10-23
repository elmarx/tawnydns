# An agenix-rekey (https://github.com/oddlama/agenix-rekey) secret generator creating tokens.
#
#   age.secrets.tawnydns-key = {
#     rekeyFile = ./secrets/tawnydns.key.age;
#     # only used to generate tokens, not deployed
#     intermediary = true;
#   };
#   age.secrets.acme-dns-token = {
#     rekeyFile = ./secrets/acme-dns-token.age;
#     generator = inputs.tawnydns.lib.agenixTokenGenerator {
#       key = config.age.secrets.tawnydns-key;
#       permissions = [
#         { zone = "example.com"; acme = [ "*" ]; }
#         { zone = "example.org"; names = [ "www" ]; types = [ "A" "AAAA" ]; }
#       ];
#     };
#   };
#
# Each permission takes the options of `tawnydns token create`: `zone`, `acme`, `names`,
# `anyName`, `types` and `anyType`. A permission with just a `zone` grants full access to it.
#
# Being a dependency, a newer private key causes `agenix generate` to regenerate the token.
# Changed permissions don't, use `agenix generate --force` (or delete the token) for that.
{ self }:
{
  key,
  permissions,
}:
assert builtins.isList permissions && permissions != [ ];
{
  dependencies = [ key ];
  script =
    {
      pkgs,
      lib,
      decrypt,
      deps,
      ...
    }:
    let
      # the pkgs passed by agenix-rekey don't include the overlay
      tawnydns = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      flags =
        {
          zone,
          acme ? [ ],
          names ? [ ],
          anyName ? false,
          types ? [ ],
          anyType ? false,
        }:
        [ zone ]
        ++ lib.concatMap (n: [
          "--acme"
          n
        ]) acme
        ++ lib.concatMap (n: [
          "--name"
          n
        ]) names
        ++ lib.optional anyName "--any-name"
        ++ lib.concatMap (t: [
          "--type"
          t
        ]) types
        ++ lib.optional anyType "--any-type";
      create =
        i: permission:
        "${tawnydns} token create ${lib.escapeShellArgs (flags permission)} "
        + lib.optionalString (i > 0) "--append - "
        + ''--private-key-file <(printf '%s\n' "$key")'';
    in
    # the private key is only kept in memory and passed by pipes, never written to disk
    ''
      set -euo pipefail
      key=$(${decrypt} ${lib.escapeShellArg (lib.head deps).file})
      ${lib.concatStringsSep " \\\n  | " (lib.imap0 create permissions)}
    '';
}
