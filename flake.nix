{
  inputs =
    {
      nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

      zig-overlay.url = "github:mitchellh/zig-overlay";
      zig-overlay.inputs.nixpkgs.follows = "nixpkgs";

      gitignore.url = "github:hercules-ci/gitignore.nix";
      gitignore.inputs.nixpkgs.follows = "nixpkgs";

      flake-utils.url = "github:numtide/flake-utils";

      binned_allocator.url = "https://gist.github.com/antlilja/8372900fcc09e38d7b0b6bbaddad3904/archive/6c3321e0969ff2463f8335da5601986cf2108690.tar.gz";
      binned_allocator.flake = false;

      diffz.url = "https://github.com/ziglibs/diffz/archive/90353d401c59e2ca5ed0abe5444c29ad3d7489aa.tar.gz";
      diffz.flake = false;

      known_folders.url = "https://github.com/ziglibs/known-folders/archive/fa75e1bc672952efa0cf06160bbd942b47f6d59b.tar.gz";
      known_folders.flake = false;
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
