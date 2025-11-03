let
  # golang pinned to 1.24.0
  # go to https://www.nixhub.io/packages/go to the list of available versions
  nixpkgs =
    fetchTarball
    "https://github.com/NixOS/nixpkgs/archive/076e8c6678d8c54204abcb4b1b14c366835a58bb.tar.gz";
  pkgs = import nixpkgs {
    config = {};
    overlays = [];
  };
  pre-commit = pkgs.callPackage ./nix/precommit.nix {};
in
  pkgs.mkShellNoCC {
    packages = with pkgs; [
      go # v1.24.0
      delve # v1.25.0
    ];
    shellHook = ''
      ${pre-commit.shellHook}
    '';
    buildInputs = pre-commit.enabledPackages;
  }
