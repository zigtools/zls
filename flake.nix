{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";
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
        zig = zig-overlay.packages.${system}.master;
        inherit (pkgs) lib;

        sources = builtins.fromJSON (lib.fileContents ./sources.json);
        deps = pkgs.callPackage ./deps.nix { };

        zlsFor = { data_version ? null, langref ? null }:
          let
            buildOption = opt: val: lib.optionalString (val != null) "-D${opt}=${val}";
          in
          pkgs.stdenvNoCC.mkDerivation {
            inherit data_version langref;
            name = "zls";
            version = "master";
            src = gitignoreSource ./.;
            nativeBuildInputs = [ zig ];
            dontConfigure = true;
            dontInstall = true;
            doCheck = true;
            buildPhase = ''
              runHook preBuild
              mkdir -p .cache
              ln -s ${deps} .cache/p
              zig build install --cache-dir $PWD/zig-cache --global-cache-dir $PWD/.cache --prefix $out \
                -Dcpu=baseline -Doptimize=ReleaseSafe ${buildOption "data_version" data_version} ${buildOption "version_data_path" langref}
              runHook postBuild
            '';
            checkPhase = ''
              runHook preCheck
              zig build test --cache-dir $PWD/zig-cache --global-cache-dir $PWD/.cache -Dcpu=baseline ${buildOption "version_data_path" langref}
              runHook postCheck
            '';
          };

        zlsPackages = lib.mapAttrs'
          (version: info: {
            name = "dv_" + version;
            value = zlsFor {
              data_version = version;
              langref = pkgs.fetchurl {
                inherit (info) hash;
                url = info.langref;
              };
            };
          })
          sources;
      in
      rec {
        formatter = nixpkgs.legacyPackages.${system}.nixpkgs-fmt;
        packages = zlsPackages // { default = zlsPackages.dv_master; };
      }
    );
}
