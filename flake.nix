{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";

    flake-utils.url = "github:numtide/flake-utils";

    known-folders.url = "github:ziglibs/known-folders";
    known-folders.flake = false;

    tres.url = "github:ziglibs/tres";
    tres.flake = false;
  };

  outputs = { self, nixpkgs, zig-overlay, gitignore, flake-utils, known-folders, tres }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      inherit (gitignore.lib) gitignoreSource;
    in
    flake-utils.lib.eachSystem systems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = zig-overlay.packages.${system}.master;
      in
      rec {
        packages.default = packages.zls;
        packages.zls = pkgs.stdenvNoCC.mkDerivation {
          name = "zls";
          version = "master";
          src = gitignoreSource ./.;
          nativeBuildInputs = [ zig ];
          dontConfigure = true;
          dontInstall = true;
          buildPhase = ''
            mkdir -p $out
            zig build install -Dcpu=baseline -Doptimize=ReleaseSafe -Ddata_version=master -Dtres=${tres}/tres.zig -Dknown-folders=${known-folders}/known-folders.zig --prefix $out
          '';
          XDG_CACHE_HOME = ".cache";
        };
      }
    );
}
