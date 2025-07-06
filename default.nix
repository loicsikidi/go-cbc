{ pkgs ? import <nixpkgs> { }, }: {
  pre-commit-check = pkgs.callPackage ./nix/pre-commit.nix { };
}
