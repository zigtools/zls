{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";

    langref.url = "https://raw.githubusercontent.com/ziglang/zig/a685ab1499d6560c523f0dbce2890dc140671e43/doc/langref.html.in";
    langref.flake = false;
  };

  outputs =
    {
      self,
      nixpkgs,
      zig-overlay,
      gitignore,
      langref,
    }:
    let
      forAllSystems =
        f:
        nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );
      inherit (gitignore.lib) gitignoreSource;
    in
    {
      formatter = forAllSystems ({ system, pkgs }: pkgs.nixfmt-rfc-style);
      packages = forAllSystems (
        { system, pkgs }:
        let
          zig = zig-overlay.packages.${system}.master;
          zls = pkgs.stdenvNoCC.mkDerivation {
            name = "zls";
            version = "master";
            src = gitignoreSource ./.;
            nativeBuildInputs = [ zig ];
            dontConfigure = true;
            dontInstall = true;
            doCheck = true;
            buildPhase = ''
              mkdir -p .cache
              ln -s ${pkgs.callPackage ./deps.nix { }} .cache/p
              zig build install --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=${langref} -Dcpu=baseline -Doptimize=ReleaseSafe --prefix $out
            '';
            checkPhase = ''
              zig build test --cache-dir $(pwd)/.zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=${langref} -Dcpu=baseline
            '';
          };
        in
        {
          inherit zls;
          default = zls;
        }
      );
    };
}
