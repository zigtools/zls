let
  pkgs = import <nixpkgs> {};
  zig-overlay = pkgs.fetchFromGitHub {
    owner = "arqv";
    repo = "zig-overlay";
    rev = "5b9504b8bff072553051d6e130727f7f5c0715c3";
    sha256 = "sha256-NDm5qT6/qr789IhI2dsQxrR5/Mr7cXVj17x/+tl3pDE=";
  };
  gitignoreSrc = pkgs.fetchFromGitHub {
    owner = "hercules-ci";
    repo = "gitignore";
    rev = "c4662e662462e7bf3c2a968483478a665d00e717";
    sha256 = "1npnx0h6bd0d7ql93ka7azhj40zgjp815fw2r6smg8ch9p7mzdlx";
  };
  inherit (import gitignoreSrc { inherit (pkgs) lib; }) gitignoreSource;
  zig-default = (import zig-overlay { inherit pkgs; }).master.latest;
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
  '';
  XDG_CACHE_HOME = ".cache";
}
