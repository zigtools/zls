{
  linkFarm,
  fetchzip,
  fetchgit,
}:
linkFarm "zig-packages" [
  {
    name = "known_folders-0.0.0-Fy-PJiLLAABzqCdF6GWFmE36oCwioOh6Uxj4FF1Neanr";
    path = fetchzip {
      url = "https://github.com/ziglibs/known-folders/archive/c7a8a1974ccf8b5b022ee7f4b13fd734cdd89ae1.tar.gz";
      hash = "sha256-rgFVAybMdYnRdwZBUXZNr1TRaWmgjgiim/isxOMTxRg=";
    };
  }
  {
    name = "diffz-0.0.1-G2tlISvOAQDORzPTSxDgiKwlHuADKeJMdJrw4kRfLufj";
    path = fetchzip {
      url = "https://github.com/ziglibs/diffz/archive/aac8aa99c436ab8277b0711922aad062c0167b12.tar.gz";
      hash = "sha256-GQ4iCZSSpVvdDQteoi02keLSqSoDOSQPH8eihum++Z0=";
    };
  }
  {
    name = "lsp_kit-0.1.0-bi_PL9o2DADHS1PDra3MGz1MXnsboN_ewNvrc419z7Fb";
    path = fetchzip {
      url = "https://github.com/zigtools/lsp-kit/archive/3e1058db66079911fdde82f833fdce6856e0a706.tar.gz";
      hash = "sha256-vsTBPP9Rf7xoVyGyi3+j9a03mLqU/gwrdDKIpFTH2v0=";
    };
  }
]
