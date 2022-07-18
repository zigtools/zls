{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    zig-overlay.url = "github:arqv/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };
  
  outputs = {self, nixpkgs, zig-overlay, gitignore }:
    let
      inherit (gitignore.lib) gitignoreSource;
      zls-derivation-fn = (system: nixpkgs.legacyPackages.${system}.stdenvNoCC.mkDerivation {
        name = "zls";
        version = "master";
        src = gitignoreSource ./.;
        nativeBuildInputs = [
          zig-overlay.packages.${system}.master.latest
        ];
        dontConfigure = true;
        dontInstall = true;
        buildPhase = ''
          mkdir -p $out
          zig build install -Drelease-safe=true -Ddata_version=master --prefix $out
        '';
        XDG_CACHE_HOME = ".cache";
      });
    in {
      packages = rec {
        x86_64-linux.zls = zls-derivation-fn "x86_64-linux";
        aarch64-linux.zls = zls-derivation-fn "aarch64-linux";
        x86_64-darwin.zls = zls-derivation-fn "x86_64-darwin";
        aarch64-darwin.zls = zls-derivation-fn "aarch64-darwin";

        x86_64-linux.default = x86_64-linux.zls;
        aarch64-linux.default = aarch64-linux.zls;
        x86_64-darwin.default = x86_64-darwin.zls;
        aarch64-darwin.default = aarch64-darwin.zls;
      };
  };
}
