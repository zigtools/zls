{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

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
          zig = zig-overlay.packages.${system}."0.14.0";
          gitignoreSource = gitignore.lib.gitignoreSource;
          target = builtins.replaceStrings ["darwin"] ["macos"] system;
          revision = self;
        in {
          formatter.${system} = pkgs.alejandra;
          packages.${system} = rec {
            default = zls;
            zls = pkgs.stdenvNoCC.mkDerivation {
              name = "zls";
              version = "0.14.0";
              meta.mainProgram = "zls";
              src = gitignoreSource ./.;
              nativeBuildInputs = [zig];
              dontConfigure = true;
              dontInstall = true;
              doCheck = true;
              buildPhase = ''
                NO_COLOR=1 # prevent escape codes from messing up the `nix log`
                PACKAGE_DIR=${pkgs.callPackage ./deps.nix {zig = zig;}}
                zig build install --global-cache-dir $(pwd)/.cache --system $PACKAGE_DIR -Dtarget=${target} -Doptimize=ReleaseSafe --prefix $out
              '';
              checkPhase = ''
                zig build test --global-cache-dir $(pwd)/.cache --system $PACKAGE_DIR -Dtarget=${target}
              '';
            };
          };
        }
      )
      ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
    );
}
