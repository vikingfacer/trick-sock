{
  description = "zig trick sock flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let leg = nixpkgs.legacyPackages.${system};
      in {
        devShells.default = leg.mkShell {
          nativeBuildInputs = [ leg.zig_0_11 leg.libpcap ];
          packages = [ leg.pkg-config ];
        };
      });
}
