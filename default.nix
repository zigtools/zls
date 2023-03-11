{ pkgs ? import <nixpkgs> { }
, system ? builtins.currentSystem
}:

let
  zig-overlay = pkgs.fetchFromGitHub {
    owner = "mitchellh";
    repo = "zig-overlay";
    rev = "62ca03d2ff30fb2920c5a1d8a2b6c87d1b68867b";
    sha256 = "1xriHeSpoL4qN5xqPiQc9S9R7Qvcl3RxHwJ5FYPjLn0=";
  };

  gitignoreSrc = pkgs.fetchFromGitHub {
    owner = "hercules-ci";
    repo = "gitignore.nix";
    rev = "a20de23b925fd8264fd7fad6454652e142fd7f73";
    sha256 = "8DFJjXG8zqoONA1vXtgeKXy68KdJL5UaXR8NtVMUbx8=";
  };

  inherit (import gitignoreSrc { inherit (pkgs) lib; }) gitignoreSource;
  zig = (import zig-overlay { inherit pkgs system; }).master;

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

  cp-phase = builtins.concatStringsSep ";" (builtins.attrValues (builtins.mapAttrs (k: v: "cp -r ${builtins.fetchTarball v.url} .cache/p/${v.hash}") zon));
in
pkgs.stdenvNoCC.mkDerivation {
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
}
