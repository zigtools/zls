{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    zig.url = "github:silversquirl/zig-flake";
    zig.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    nixpkgs,
    zig,
    gitignore,
    ...
  }: let
    forAllSystems = f: builtins.mapAttrs f nixpkgs.legacyPackages;
  in {
    formatter = forAllSystems (system: pkgs: pkgs.alejandra);

    packages = forAllSystems (system: pkgs: {
      default = zig.packages.${system}.zig_0_15_1.makePackage {
        pname = "zls";
        version = "0.15.1";
        meta.mainProgram = "zls";
        src = gitignore.lib.gitignoreSource ./.;
        doCheck = true;
        zigReleaseMode = "safe";
        depsHash = "sha256-ji4qpx3WEEIaW8/Ps5uNJHvMEA+tl6wWj3dZx0RWQpo=";
      };
    });
  };
}
