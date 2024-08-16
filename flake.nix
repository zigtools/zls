{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";

      # llvm: fix @wasmMemory{Size,Grow} for wasm64
      langref.url = "https://raw.githubusercontent.com/ziglang/zig/eb7f318ea897d51082b70c84591242735c8a2c53/doc/langref.html.in";
      langref.flake = false;
    };

  outputs = { self, nixpkgs, zig-overlay, gitignore, flake-utils, langref }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        zig = zig-overlay.packages.${system}.master;
        gitignoreSource = gitignore.lib.gitignoreSource;
      in
      rec {
        formatter = pkgs.nixpkgs-fmt;
        packages.default = packages.zls;
        packages.zls = pkgs.stdenvNoCC.mkDerivation {
          name = "zls";
          version = "master";
          src = gitignoreSource ./.;
          nativeBuildInputs = [ zig ];
          dontConfigure = true;
          dontInstall = true;
          doCheck = true;
          langref = langref;
          buildPhase = ''
            mkdir -p .cache
            ln -s ${pkgs.callPackage ./deps.nix { zig = zig; }} .cache/p
            zig build install --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=$langref -Dcpu=baseline -Doptimize=ReleaseSafe --prefix $out
          '';
          checkPhase = ''
            zig build test --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=$langref -Dcpu=baseline
          '';
        };
      }
    );
}
