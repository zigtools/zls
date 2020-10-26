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

  zig = pkgs.zig.custom {
    sha256 = "7d715ea8948611734986d8a056fdec98d0f39b064e38efcd088823c02b1afba8";
    version = "0.6.0+91a1c20e7";
  };
in
  pkgs.stdenvNoCC.mkDerivation {
    name = "zls";
    version = "master";
    src = gitignoreSource ./.;
    nativeBuildInputs = [
      zig
    ];

    dontConfigure = true;
    buildPhase = ''
      zig build -Drelease-safe=true
    '';
    installPhase = ''
      mkdir -p $out
      zig build install --prefix $out

      # write configuration according to defaults described in README.md
      cat << EOF > $out/bin/zls.json
        {
          "zig_lib_path": "${zig}/lib/zig/",
          "zig_exe_path": "${zig}/bin/zig",
          "warn_style": false,
          "enable_snippets": false,
          "enable_semantic_tokens": false,
          "operator_completions": true
        }
      EOF
    '';

    XDG_CACHE_HOME = ".";
  }
