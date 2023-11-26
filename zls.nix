{ callPackage, stdenvNoCC, gitignoreSource, zig, langref }:
stdenvNoCC.mkDerivation {
  name = "zls";
  version = "master";
  src = gitignoreSource ./.;
  nativeBuildInputs = [ zig ];
  dontConfigure = true;
  dontInstall = true;
  doCheck = true;
  langref = langref;
  buildPhase = ''
    mkdir -p .cache
    ln -s ${callPackage ./deps.nix { }} .cache/p
    zig build install --cache-dir $(pwd)/zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=$langref -Dcpu=baseline -Doptimize=ReleaseSafe --prefix $out
  '';
  checkPhase = ''
    zig build test --cache-dir $(pwd)/zig-cache --global-cache-dir $(pwd)/.cache -Dversion_data_path=$langref -Dcpu=baseline
  '';
}
