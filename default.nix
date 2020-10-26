let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  gitignore = import sources.gitignore {};
  
  zig = pkgs.stdenvNoCC.mkDerivation rec {
    name = "zig";
    version = "0.6.0+91a1c20e7";
    src = pkgs.fetchurl {
      url = "https://ziglang.org/builds/zig-linux-x86_64-${version}.tar.xz";
      sha256 = "7d715ea8948611734986d8a056fdec98d0f39b064e38efcd088823c02b1afba8";
    };
    dontConfigure = true;
    dontBuild = true;
    installPhase = ''
      mkdir -p $out $out/bin $out/doc
      mv lib/ $out/
      mv zig $out/bin
      mv langref.html $out/doc
    '';
  };
in
  pkgs.stdenvNoCC.mkDerivation {
    name = "zls";
    version = "master";
    src = gitignore.gitignoreSource ./.;
    nativeBuildInputs = [ zig ];
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
