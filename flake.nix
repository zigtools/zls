{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";

      known_folders.url = "https://github.com/ziglibs/known-folders/archive/53fe3b676f32e59d46f4fd201d7ab200e5f6cb98.tar.gz";
      known_folders.flake = false;

      tres.url = "https://github.com/ziglibs/tres/archive/d8b0c24a945da02fffdae731edd1903c6889e73c.tar.gz";
      tres.flake = false;

      diffz.url = "https://github.com/ziglibs/diffz/archive/efc91679b000a2d7f86fb40930f0a95a0d349bff.tar.gz";
      diffz.flake = false;
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
