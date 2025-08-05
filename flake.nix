{
  description = "Flake for obfuscator";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      inherit (inputs.self.lib) mkPkgs;
      systems = lib.systems.flakeExposed;
      forExposedSystems = lib.genAttrs systems;
    in
    {
      devShells = forExposedSystems (
        system: with (mkPkgs { inherit system; }); {
          default = mkShell {
            packages = [
              (haskellPackages.ghcWithPackages (
                # it will filter packages with attribute "isHaskellLibrary"
                f: # f <- haskellPackges
                with f; [
                  cabal-gild
                  cabal-install
                  haskell-language-server
                ]
              ))
            ];
            shellHook = ''
              fish
            '';
          };
        }
      );

      formatter = forExposedSystems (system: (mkPkgs { inherit system; }).nixfmt);

      legacyPackages = forExposedSystems (
        system:
        inputs.self.overlays.default null (mkPkgs {
          inherit system;
        })
      );

      lib.mkPkgs =
        {
          nixpkgsInstance ? inputs.nixpkgs,
          config ? { },
          overlays ? [ ],
          system,
        }:
        import nixpkgsInstance {
          inherit system;
          config = {
            allowAliases = false;
          }
          // config;
          overlays = [
            inputs.self.overlays.default
            (final: prev: { path = "${nixpkgsInstance}"; })
          ]
          ++ overlays;
        };

      overlays.default = final: prev: rec {
        obfuscator = prev.haskellPackages.callPackage (
          {
            lib,
            mkDerivation,
            base,
            bytestring,
            containers,
            crypton,
            directory,
            filepath,
            memory,
            optparse-applicative,
            random,
            text,
          }:
          mkDerivation {
            pname = "obfuscator";
            version = "1.0.0.0";
            src = ./.;
            isLibrary = false;
            isExecutable = true;
            executableHaskellDepends = [
              base
              bytestring
              containers
              crypton
              directory
              filepath
              memory
              optparse-applicative
              random
              text
            ];
            license = lib.licenses.gpl3Only;
            mainProgram = "obfuscator";
          }
        ) { };
        haskellPackages = prev.haskellPackages.override {
          overrides = hsfinal: hsprev: { inherit obfuscator; };
        };
      };
    };

}
