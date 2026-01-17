{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    zig-overlay.url = "github:mitchellh/zig-overlay";
    zig-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    zig-overlay,
  }: let
    lib = nixpkgs.lib;
    parseVersionFieldFromZon = name:
      lib.pipe ./build.zig.zon [
        builtins.readFile
        (builtins.match ".*\n[[:space:]]*\.${name}[[:space:]]=[[:space:]]\"([^\"]+)\".*")
        builtins.head
      ];
    zlsVersionShort = parseVersionFieldFromZon "version";
    zlsVersionFull =
      zlsVersionShort
      + (
        if (builtins.length (builtins.splitVersion zlsVersionShort)) == 3
        then ""
        else "+" + lib.replaceString "-" "." (self.dirtyShortRev or self.shortRev)
      );
  in
    builtins.foldl' lib.recursiveUpdate {} (
      builtins.map
      (
        system: let
          pkgs = nixpkgs.legacyPackages.${system};
          fs = lib.fileset;
          zig = zig-overlay.packages.${system}.master;
          target = builtins.replaceStrings ["darwin"] ["macos"] system;
        in {
          formatter.${system} = pkgs.alejandra;
          packages.${system} = rec {
            default = zls;
            zls = pkgs.stdenvNoCC.mkDerivation {
              name = "zls";
              version = zlsVersionShort;
              meta.mainProgram = "zls";
              src = fs.toSource {
                root = ./.;
                fileset = fs.intersection (fs.fromSource (lib.sources.cleanSource ./.)) (
                  fs.unions [
                    ./src
                    ./tests
                    ./build.zig
                    ./build.zig.zon
                    ./deps.nix
                  ]
                );
              };
              nativeBuildInputs = [zig];
              dontInstall = true;
              doCheck = true;
              configurePhase = ''
                export ZIG_GLOBAL_CACHE_DIR=$TEMP/.cache
                PACKAGE_DIR=${pkgs.callPackage ./deps.nix {}}
              '';
              buildPhase = ''
                zig build install --system $PACKAGE_DIR -Dtarget=${target} -Doptimize=ReleaseSafe -Dversion-string=${zlsVersionFull} --color off --prefix $out
              '';
              checkPhase = ''
                zig build test --system $PACKAGE_DIR -Dtarget=${target} -Dversion-string=${zlsVersionFull} --color off
              '';
            };
          };
        }
      )
      ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"]
    );
}
