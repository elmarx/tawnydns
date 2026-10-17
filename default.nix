{
  lib,
  rustPlatform,
}:

rustPlatform.buildRustPackage {
  pname = "tawnydns";
  version = "0.1.0";

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  src = ./.;

  meta = with lib; {
    description = "Authorizing proxy for the PowerDNS API";
    homepage = "https://github.com/elmarx/tawnydns";
    license = with licenses; [
      mit
      asl20
    ];
    mainProgram = "tawnydns";
  };
}
