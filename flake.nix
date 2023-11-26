{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";

      langref.url = "https://raw.githubusercontent.com/ziglang/zig/54bbc73f8502fe073d385361ddb34a43d12eec39/doc/langref.html.in";
      langref.flake = false;
    };

  outputs = inputs:
    let
      inherit (inputs) nixpkgs zig-overlay gitignore flake-utils;
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      inherit (gitignore.lib) gitignoreSource;
    in
    flake-utils.lib.eachSystem systems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      rec {
        formatter = pkgs.nixpkgs-fmt;
        packages.default = packages.zls;
        packages.zls = pkgs.callPackage ./zls.nix {
          inherit (gitignore.lib) gitignoreSource;
          langref = inputs.langref;
          zig = zig-overlay.packages.${system}.master;
        };
      });
}
