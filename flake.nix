{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    zig-overlay,
    gitignore,
  }:
    builtins.foldl' nixpkgs.lib.recursiveUpdate {} (
      builtins.map
      (
        system: let
          pkgs = nixpkgs.legacyPackages.${system};
          zig = zig-overlay.packages.${system}.master;
          gitignoreSource = gitignore.lib.gitignoreSource;
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
              src = gitignoreSource ./.;
              nativeBuildInputs = [zig];
              dontInstall = true;
              doCheck = true;
              configurePhase = ''
                export ZIG_GLOBAL_CACHE_DIR=$TEMP/.cache
              '';
              buildPhase = ''
                PACKAGE_DIR=${pkgs.callPackage ./deps.nix {}}
                zig build install --system $PACKAGE_DIR -Dtarget=${target} -Doptimize=ReleaseSafe --color off --prefix $out
              '';
              checkPhase = ''
                zig build test --system $PACKAGE_DIR -Dtarget=${target} --color off
              '';
            };
          };
        }
      )
      ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
    );
}
