{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    zig-overlay.url = "github:arqv/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";

    flake-utils.url = "github:numtide/flake-utils";
  };
  
  outputs = {self, nixpkgs, zig-overlay, gitignore, flake-utils }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      inherit (gitignore.lib) gitignoreSource;
    in flake-utils.lib.eachSystem systems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = zig-overlay.packages.${system}.master.latest;
        known-folders = pkgs.stdenvNoCC.mkDerivation {
          name = "known-folders";
          src = pkgs.fetchFromGitHub {
            owner = "ziglibs";
            repo = "known-folders";
            rev = "9db1b99219c767d5e24994b1525273fe4031e464";
            sha256 = "sha256-eqaZxIax8C75L2UwDbVKSUZ7iThm/iWblfoaTfPyHLM=";
          };
          dontConfigure = true;
          dontInstall = true;
          buildPhase = ''
            mkdir -p $out
            cp known-folders.zig $out
          '';
        };
      in rec {
        packages.default = packages.zls;
        packages.zls = pkgs.stdenvNoCC.mkDerivation {
          name = "zls";
          version = "master";
          src = gitignoreSource ./.;
          nativeBuildInputs = [ zig ];
          buildInputs = [ known-folders ];
          dontConfigure = true;
          dontInstall = true;
          buildPhase = ''
            mkdir -p $out
            zig build install -Drelease-safe=true -Ddata_version=master -Dknown-folders=${known-folders}/known-folders.zig --prefix $out
          '';
          XDG_CACHE_HOME = ".cache";
        };
      }
  );
}
