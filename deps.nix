{
  linkFarm,
  fetchzip,
  fetchgit,
  emptyDirectory,
}:
linkFarm "zig-packages" [
  {
    name = "diffz-0.0.1-G2tlIYrNAQAQx3cuIp7EVs0xvxbv9DCPf4YuHmvubsrZ";
    path = fetchzip {
      url = "https://github.com/ziglibs/diffz/archive/aa11caef328a3f20f2493f8fd676a1dfa7819246.tar.gz";
      hash = "sha256-bdL+xLnYVzYS6T3zsw7xfLKTUCUFI0pIpQaOxV6oTis=";
    };
  }
  {
    name = "known_folders-0.0.0-Fy-PJiXKAACLbIUjxVqJRTSLc6HNnMkCSBnC5LW0Lx_v";
    path = fetchzip {
      url = "https://github.com/ziglibs/known-folders/archive/d002ad87b1f8c238eb080c185bb0b93cfd946b9d.tar.gz";
      hash = "sha256-ZhNsjtdsqu2n3LuSVNfVktwp3mSJy367R3vR7z7NOJw=";
    };
  }
  {
    name = "lsp_kit-0.1.0-bi_PLw8zDABvCWe2rD4Aqb9gx0sRXBKO0a7M0vg3AbR3";
    path = fetchzip {
      url = "https://github.com/zigtools/lsp-kit/archive/7b03f0b6801babffe76608cf3db59793902a21d6.tar.gz";
      hash = "sha256-CjWrp8fERKS5VldRvYtDFk1g4heIkX4YrpLw/eC12Q4=";
    };
  }
  # workaround: https://codeberg.org/ziglang/zig/issues/31162
  {
    name = "N-V-__8AAOncKwEm1F9c5LrT7HMNmRMYX8-fAoqpc6YyTu9X";
    path = emptyDirectory;
  }
]
