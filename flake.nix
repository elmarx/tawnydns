{
  description = "TawnyDNS, an authorizing proxy for the PowerDNS API";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    inputs@{
      self,
      flake-parts,
      nixpkgs,
      rust-overlay,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { system, pkgs, ... }:
        let
          rustPkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
        in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with rustPkgs; [
              (rust-bin.stable.latest.default.override { extensions = [ "rust-src" ]; })
              cargo-nextest
              just

              nixfmt

              opentofu
            ];
          };

          packages.default = pkgs.callPackage ./default.nix { };

          checks.agenix-generator =
            let
              tawnydns = pkgs.lib.getExe self.packages.${system}.default;
              generator = self.lib.agenixTokenGenerator {
                key = { };
                permissions = [
                  {
                    zone = "example.com";
                    acme = [ "*" ];
                  }
                  {
                    zone = "example.org";
                    names = [ "www" ];
                    types = [ "AAAA" ];
                  }
                ];
              };
              # an unencrypted key stands in for the age-encrypted one
              script = generator.script {
                inherit pkgs;
                inherit (pkgs) lib;
                decrypt = "cat";
                deps = [ { file = "tawnydns.key"; } ];
              };
            in
            pkgs.runCommand "agenix-generator" { } ''
              ${tawnydns} keygen -o tawnydns.key
              ${tawnydns} keygen --public --private-key-file tawnydns.key -o tawnydns.pub
              (${script}) > token
              ${tawnydns} token inspect --public-key-file tawnydns.pub token | tee claim
              grep -q '"example.com"' claim
              grep -q '"example.org"' claim
              touch $out
            '';
        };

      flake = {
        overlays.default = final: _prev: {
          tawnydns = self.packages.${final.stdenv.hostPlatform.system}.default;
        };

        nixosModules.default = {
          imports = [ ./nixos-module.nix ];
          nixpkgs.overlays = [ self.overlays.default ];
        };

        lib.agenixTokenGenerator = import ./agenix-generator.nix { inherit self; };
      };
    };
}
