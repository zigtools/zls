{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

    zig-flake.url = "github:silversquirl/zig-flake";
    zig-flake.inputs.nixpkgs.follows = "nixpkgs";

    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    nixpkgs,
    zig-flake,
    gitignore,
    ...
  }: let
    forAllSystems = f: builtins.mapAttrs f nixpkgs.legacyPackages;

    mkPackage = {
      zig,
      version,
      src,
      depsHash ? nixpkgs.lib.fakeHash,
    }:
      zig.makePackage {
        inherit version src depsHash;
        pname = "zls";
        meta.mainProgram = "zls";
        doCheck = true;
        zigReleaseMode = "safe";
      };
  in {
    formatter = forAllSystems (system: pkgs: pkgs.alejandra);

    packages = forAllSystems (system: pkgs: rec {
      default = master;
      zls = master; # compat
      master = mkPackage {
        zig = zig-flake.packages.${system}.nightly;
        version = "master";
        src = gitignore.lib.gitignoreSource ./.;
        depsHash = "sha256-ji4qpx3WEEIaW8/Ps5uNJHvMEA+tl6wWj3dZx0RWQpo=";
      };
      zls_0_15_0 = mkPackage {
        zig = zig-flake.packages.${system}.zig_0_15_1;
        version = "0.15.0";
        src = pkgs.fetchFromGitHub {
          owner = "zigtools";
          repo = "zls";
          rev = "0.15.0";
          hash = "sha256-GFzSHUljcxy7sM1PaabbkQUdUnLwpherekPWJFxXtnk=";
        };
        depsHash = "sha256-lyqTRZxsipitdP1gFupdzMH+0crP7LXRRCYUWkjhKEg=";
      };
      zls_0_14_0 = mkPackage {
        zig = zig-flake.packages.${system}.zig_0_14_1;
        version = "0.14.0";
        src = pkgs.fetchFromGitHub {
          owner = "zigtools";
          repo = "zls";
          rev = "0.14.0";
          hash = "sha256-A5Mn+mfIefOsX+eNBRHrDVkqFDVrD3iXDNsUL4TPhKo=";
        };
        depsHash = "sha256-5ub+AA2PYuHrzPfouii/zfuFmQfn6mlMw4yOUDCw3zI=";
      };
    });
  };
}
