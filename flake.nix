{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";

      binned_allocator.url = "https://gist.github.com/silversquirl/c1e4840048fdf48e669b6eac76d80634/archive/8bbe137e65f26854ff936046d884a45d4fa156de.tar.gz";
      binned_allocator.flake = false;

      diffz.url = "https://github.com/ziglibs/diffz/archive/2fd03fc72760a700e41f30f2b180f26e11c3365b.tar.gz";
      diffz.flake = false;

      known_folders.url = "https://github.com/ziglibs/known-folders/archive/d13ba6137084e55f873f6afb67447fe8906cc951.tar.gz";
      known_folders.flake = false;

      tres.url = "https://github.com/ziglibs/tres/archive/220d01f3931595e3a2e2a6a0693363c0bfaf47e9.tar.gz";
      tres.flake = false;
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
        zon = builtins.fromJSON (
          builtins.concatStringsSep "" [
            "{"
            (builtins.replaceStrings [ "}, " ] [ "}" ]
              (builtins.replaceStrings [ " ." " =" "\n" ", }" ] [ "\"" "\" :" "" "}" ]
                (builtins.replaceStrings [ ".{" ] [ "{" ]
                  (builtins.concatStringsSep " "
                    (builtins.filter builtins.isString
                      (builtins.split "[ \n]+"
                        (builtins.elemAt
                          (builtins.match ".*dependencies = .[{](.*)[}].*" (builtins.readFile ./build.zig.zon))
                          0)))))))
          ]
        );
        cp-phase = builtins.concatStringsSep ";" (builtins.attrValues (builtins.mapAttrs (k: v: "cp -r ${inputs.${k}} .cache/p/${v.hash}") zon));
      in
      rec {
        formatter = nixpkgs.legacyPackages.${system}.nixpkgs-fmt;
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
            mkdir -p .cache/{p,z,tmp}
            ${cp-phase}
            zig build install --cache-dir $(pwd)/zig-cache --global-cache-dir $(pwd)/.cache -Dcpu=baseline -Doptimize=ReleaseSafe -Ddata_version=master --prefix $out
          '';
        };
      }
    );
}
