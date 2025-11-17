{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    zig-overlay,
  }:
    builtins.foldl' nixpkgs.lib.recursiveUpdate {} (
      builtins.map
      (
        system: let
          pkgs = nixpkgs.legacyPackages.${system};
          fs = pkgs.lib.fileset;
          zig = zig-overlay.packages.${system}.master;
          target = builtins.replaceStrings ["darwin"] ["macos"] system;
          revision = self;
        in {
          formatter.${system} = pkgs.alejandra;
          packages.${system} = rec {
            default = zls;
            zls = pkgs.stdenvNoCC.mkDerivation {
              name = "zls";
              version = "master";
              meta.mainProgram = "zls";
              src = fs.toSource {
                root = ./.;
                fileset = fs.intersection (fs.fromSource (pkgs.lib.sources.cleanSource ./.)) (
                  fs.unions [
                    ./src
                    ./tests
                    ./build.zig
                    ./build.zig.zon
                    ./deps.nix
                  ]
                );
              };
              nativeBuildInputs = [zig];
              configurePhase = ''
                export ZIG_GLOBAL_CACHE_DIR=$TEMP/.cache
                PACKAGE_DIR=${pkgs.callPackage ./deps.nix {}}
              '';
              buildPhase = ''
                zig build --system $PACKAGE_DIR -Dtarget=${target} -Doptimize=ReleaseSafe --color off
              '';
              installPhase = ''
                cp -r zig-out $out
              '';
            };
          };
        }
      )
      ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
    );
}
