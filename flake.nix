{
  description = "Development shells with the toolchains CI's build and web jobs use";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    let
      # The pinned wasm-bindgen CLI below is published for this system only.
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      # The build job runs the runner image's default stable Rust, which is 1.100.0 as of
      # 2026-11. Bump this when the runner's stable moves.
      buildRust = pkgs.rust-bin.stable."1.100.0".minimal.override {
        extensions = [
          "clippy"
          "rustfmt"
        ];
      };

      # The web job's RUSTUP_TOOLCHAIN, with the wasm32 target and clippy.
      webRust = pkgs.rust-bin.stable."1.97.1".minimal.override {
        extensions = [ "clippy" ];
        targets = [ "wasm32-unknown-unknown" ];
      };

      # The web job's WASM_BINDGEN_VERSION and WASM_BINDGEN_SHA256; scripts/build-web.sh
      # refuses a CLI whose version differs from Cargo.lock's.
      wasmBindgen = pkgs.stdenvNoCC.mkDerivation rec {
        pname = "wasm-bindgen-cli";
        version = "0.2.127";
        src = pkgs.fetchurl {
          url = "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}/wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz";
          sha256 = "61d4a7dc85acfa0d2354ccc0b8361928c7e52a746d17f28ebaa795ed3dc1614a";
        };
        installPhase = ''
          mkdir -p $out/bin
          cp wasm-bindgen wasm-bindgen-test-runner wasm2es6js $out/bin/
        '';
      };

      # ring compiles C for wasm32. The wrapped clang adds the host's glibc headers, which
      # break that build, so the shell names the unwrapped one.
      wasmClang = pkgs.llvmPackages.clang-unwrapped;
      wasmLlvm = pkgs.llvmPackages.llvm;
    in
    {
      devShells.${system} = {
        # `nix develop -c cargo clippy --locked --all-targets -- -D warnings`
        default = pkgs.mkShell { packages = [ buildRust ]; };

        # `nix develop .#web -c cargo clippy --locked -p tau-web --target wasm32-unknown-unknown ...`
        web = pkgs.mkShell {
          packages = [
            webRust
            wasmBindgen
            wasmLlvm
          ];
          CC_wasm32_unknown_unknown = "${wasmClang}/bin/clang";
          AR_wasm32_unknown_unknown = "${wasmLlvm}/bin/llvm-ar";
        };
      };
    };
}
