let
  zig-overlay = import (builtins.fetchGit {
    url = "https://github.com/arqv/zig-overlay.git";
    rev = "a56601116906a2f192702e0b97487b8e7f796fdc";
  });
  pkgs = import <nixpkgs> { overlays = [ zig-overlay ]; };
  gitignoreSrc = pkgs.fetchFromGitHub {
    owner = "hercules-ci";
    repo = "gitignore";
    rev = "c4662e662462e7bf3c2a968483478a665d00e717";
    sha256 = "1npnx0h6bd0d7ql93ka7azhj40zgjp815fw2r6smg8ch9p7mzdlx";
  };
  inherit (import gitignoreSrc { inherit (pkgs) lib; }) gitignoreSource;
  zig-default = pkgs.zig.master;
in { zig ? zig-default, extraConfig ? { } }:
pkgs.stdenvNoCC.mkDerivation {
  name = "zls";
  version = "master";
  src = gitignoreSource ./.;
  nativeBuildInputs = [ zig ];
  dontConfigure = true;
  dontInstall = true;
  buildPhase = ''
    mkdir -p $out
    zig build install -Drelease-safe=true -Ddata_version=master --prefix $out
    cat << EOF > $out/bin/zls.json
      ${
        builtins.toJSON ({
          zig_lib_path = "${zig}/lib/zig/";
          zig_exe_path = "${zig}/bin/zig";
          warn_style = false;
          enable_snippets = false;
          enable_semantic_tokens = false;
          operator_completions = true;
        } // extraConfig)
      }
    EOF
  '';
  XDG_CACHE_HOME = ".cache";
}
