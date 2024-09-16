# generated by zon2nix (https://github.com/Cloudef/zig2nix)

{ lib, linkFarm, fetchurl, fetchgit, runCommandLocal, zig, name ? "zig-packages" }:

with builtins;
with lib;

let
  unpackZigArtifact = { name, artifact }: runCommandLocal name {
      nativeBuildInputs = [ zig ];
    } ''
      hash="$(zig fetch --global-cache-dir "$TMPDIR" ${artifact})"
      mv "$TMPDIR/p/$hash" "$out"
      chmod 755 "$out"
    '';

  fetchZig = { name, url, hash }: let
    artifact = fetchurl { inherit url hash; };
  in unpackZigArtifact { inherit name artifact; };

  fetchGitZig = { name, url, hash }: let
    parts = splitString "#" url;
    url_base = elemAt parts 0;
    url_without_query = elemAt (splitString "?" url_base) 0;
    rev_base = elemAt parts 1;
    rev = if match "^[a-fA-F0-9]{40}$" rev_base != null then rev_base else "refs/heads/${rev_base}";
  in fetchgit {
    inherit name rev hash;
    url = url_without_query;
    deepClone = false;
  };

  fetchZigArtifact = { name, url, hash }: let
    parts = splitString "://" url;
    proto = elemAt parts 0;
    path = elemAt parts 1;
    fetcher = {
      "git+http" = fetchGitZig { inherit name hash; url = "http://${path}"; };
      "git+https" = fetchGitZig { inherit name hash; url = "https://${path}"; };
      http = fetchZig { inherit name hash; url = "http://${path}"; };
      https = fetchZig { inherit name hash; url = "https://${path}"; };
      file = unpackZigArtifact { inherit name; artifact = /. + path; };
    };
  in fetcher.${proto};
in linkFarm name [
  {
    name = "12209d2738a2e1dbd3781c2e5f01a2ea877dcfeea53efdfa1913247297d328e6b207";
    path = fetchZigArtifact {
      name = "known_folders";
      url = "https://github.com/ziglibs/known-folders/archive/47076c6b11214a218e9244471d8762310820911a.tar.gz";
      hash = "sha256-M5BAjnlfdHtpZFVXOUPfxjY+JUMtkLBs97dudQkIeto=";
    };
  }
  {
    name = "1220102cb2c669d82184fb1dc5380193d37d68b54e8d75b76b2d155b9af7d7e2e76d";
    path = fetchZigArtifact {
      name = "diffz";
      url = "https://github.com/ziglibs/diffz/archive/ef45c00d655e5e40faf35afbbde81a1fa5ed7ffb.tar.gz";
      hash = "sha256-Hdj0Z4Fxv9JHaqdHQ+SLzhCq0rkMLfA406xrDvN/w7o=";
    };
  }
  {
    name = "122054fe123b819c1cca154f0f89dd799832a639d432287a2371499bcaf7b9dcb7a0";
    path = fetchZigArtifact {
      name = "lsp-codegen";
      url = "https://github.com/zigtools/zig-lsp-codegen/archive/6b34887189def7c859307f4a9fc436bc5f2f04c9.tar.gz";
      hash = "sha256-Q1Lm0YornfymWeryFdKe0AXsOJxhxHH72U1IcMxiVtA=";
    };
  }
  {
    name = "122022a478dccaed1309fb5d022f4041eec45d40c93a855ed24fad970774c2426d91";
    path = fetchZigArtifact {
      name = "tracy";
      url = "https://github.com/wolfpld/tracy/archive/refs/tags/v0.11.1.tar.gz";
      hash = "sha256-LBHKgW8rdWvicw+GsAkpIEGfPavHpxc4Kf/Yl9kYiKE=";
    };
  }
]