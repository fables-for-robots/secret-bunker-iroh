{
  description = "secret-bunker-iroh";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    systems.url = "github:nix-systems/default";

  };

  outputs = { self, nixpkgs, systems, ... }@inputs:
    let
      eachSystem = f:
        nixpkgs.lib.genAttrs (import systems)
        (system: f system nixpkgs.legacyPackages.${system});
    in {

      devShells = eachSystem (system: pkgs: {
        default = pkgs.mkShell {
          shellHook = ''
            # Set here the env vars you want to be available in the shell
          '';

          packages = with pkgs; [ rustc cargo rustfmt clippy rust-analyzer kind kubectl kubernetes-helm ];
        };
      });

      packages = eachSystem (system: pkgs:
        let
          operator = pkgs.rustPlatform.buildRustPackage {
            pname = "secret-bunker-operator";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            buildAndTestSubdir = "operator";
            # Tests run in CI via the cargo-native `test` job; skip them in the
            # nix sandbox, which blocks the real UDP/QUIC socket binds the
            # iroh integration tests need (EPERM under sandbox-exec on Darwin).
            doCheck = false;
          };
        in
        {
          inherit operator;
        });
    };
}
