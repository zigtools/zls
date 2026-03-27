{
  linkFarm,
  fetchzip,
  fetchgit,
  emptyDirectory,
}:
linkFarm "zig-packages" [
  {
    name = "known_folders-0.0.0-Fy-PJk7KAAC41mQXzmFyGa0Q7tvmQjatENkREa6Gc4zu";
    path = fetchzip {
      url = "https://github.com/ziglibs/known-folders/archive/4575ac4088eb7d0c8421d5b3d642f19de392d898.tar.gz";
      hash = "sha256-YE4KRNvrqzMtB7sSPnnbhwCokfNP7RqNtO1QVgwbiBc=";
    };
  }
  {
    name = "diffz-0.0.1-G2tlIXvNAQCPPTvl-leqv4d5nfEdwLw2lfE11P7EGKhy";
    path = fetchzip {
      url = "https://github.com/ziglibs/diffz/archive/d93d5737d2c19a2fb279c8dcaa80a4ce35529a3b.tar.gz";
      hash = "sha256-1IDqdr0+74IlH76eovC6m5Ww6bNMAAyHFt1ukat/UXk=";
    };
  }
  {
    name = "lsp_kit-0.1.0-bi_PL_kyDACVTEhLaMq2-PJx0MocqRyjXDAN0ybMUyQQ";
    path = fetchzip {
      url = "https://github.com/zigtools/lsp-kit/archive/ec325a3c33d1da7708cf513355208f74d9560580.tar.gz";
      hash = "sha256-60F2BOCrl3CreQFmpH3HAz6zzxd3VgJ3iSEkP39gtgQ=";
    };
  }
  # workaround: https://codeberg.org/ziglang/zig/issues/31162
  {
    name = "N-V-__8AAOncKwEm1F9c5LrT7HMNmRMYX8-fAoqpc6YyTu9X";
    path = emptyDirectory;
  }
]
