{
  pkgs,
  crate2nix-tools,
}: let
  generated = crate2nix-tools.generatedCargoNix {
    name = "io-uring-test";
    src = ./.;
  };
  called = pkgs.callPackage "${generated}/default.nix" {};
in
  called.rootCrate.build
