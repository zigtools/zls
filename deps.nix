{
  linkFarm,
  fetchzip,
  fetchgit,
}:
linkFarm "zig-packages" [
  {
    name = "diffz-0.0.1-G2tlISLPAQDzXkUIRWWUfdgIsIb1dAyVwRPXMt5kRpui";
    path = fetchzip {
      url = "https://github.com/ziglibs/diffz/archive/669e6ed7470100bfd9d2aa9f6f96b93c45996179.tar.gz";
      hash = "sha256-tEMWxY7jhp5OGJHejfGCkXuMtpbnp6hFetms8Zk3PYs=";
    };
  }
  {
    name = "known_folders-0.0.0-Fy-PJovNAAAtqbaXgBhV6G-Z4-WNo7P0Rov-x-npZq21";
    path = fetchzip {
      url = "https://github.com/ziglibs/known-folders/archive/bafef170a73c064dc706fcfbdc2e406a35681a9c.tar.gz";
      hash = "sha256-zn152a/Ripd1NE8bm9/6R5Y9IGIEBdNmz+Kzp+/54Gc=";
    };
  }
  {
    name = "lsp_kit-0.1.0-bi_PLxUtDADXnL1XmZTnZ0u5fTX1rVkBFd9BurkxVZ0C";
    path = fetchzip {
      url = "https://github.com/zigtools/lsp-kit/archive/c1bf170380de0f2ddb64ca31ece5582c98922df2.tar.gz";
      hash = "sha256-ngCiSx7KBf3KhKgMx/Z9sC90+fZ9SjB3Ov1sqoWJVlI=";
    };
  }
]
