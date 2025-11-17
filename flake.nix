{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    zig-flake.url = "github:silversquirl/zig-flake";
    zig-flake.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    zig-flake,
  }:
    builtins.foldl' nixpkgs.lib.recursiveUpdate {} (
      builtins.map
      (
        system: let
          target = builtins.replaceStrings ["darwin"] ["macos"] system;
          pkgs = nixpkgs.legacyPackages.${system};
          fs = pkgs.lib.fileset;
          # Must be kept in sync with the 'minimum_zig_version' in 'build.zig.zon'
          zig = zig-flake.packages.${system}.zig_0_16_0_dev_1657;
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
