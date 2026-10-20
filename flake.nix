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
          cli = pkgs.rustPlatform.buildRustPackage {
            pname = "secret-bunker-iroh";
            inherit ((pkgs.lib.importTOML ./Cargo.toml).package) version;
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "--package" "secret-bunker-iroh" ];
            # See operator.
            doCheck = false;
            meta.mainProgram = "secret-bunker-iroh";
          };
        in
        {
          inherit operator;
          secret-bunker-iroh = cli;
          default = cli;
        });
    };
}
