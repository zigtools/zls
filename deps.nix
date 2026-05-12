{
  linkFarm,
  fetchzip,
  fetchgit,
}:
linkFarm "zig-packages" [
  {
    name = "known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70";
    path = fetchzip {
      url = "https://github.com/ziglibs/known-folders/archive/207c34a16e4365edc20d92c7892f962b3bed46e8.tar.gz";
      hash = "sha256-9hMnEc3ktnFTZT28hjaOkafjSUXEI+SNIO9GMcJrBfA=";
    };
  }
  {
    name = "diffz-0.0.1-G2tlIfLNAQCc06RFk0tFGj2M-X-id4WHFkMVw2JoMILR";
    path = fetchzip {
      url = "https://github.com/ziglibs/diffz/archive/d080c1eb782fff15068cabb3b82da85ce6054b74.tar.gz";
      hash = "sha256-a9O9Wt8QkdMnSznWiowRoMlQm1JCFuxLwZR3SDHsGHs=";
    };
  }
  {
    name = "lsp_kit-0.1.0-bi_PL3IyDACfp1xdTnkiOHEok2YpPCCCJHuuOcNzjl1D";
    path = fetchzip {
      url = "https://github.com/zigtools/lsp-kit/archive/b886a2b0d5cee85ecbcc3089b863f7517cc9ff7f.tar.gz";
      hash = "sha256-367wPydvnpl9RYlTrXwk4bZ/ui9DbYjeY/VDYs7ZJRs=";
    };
  }
]
