{
  inputs = {
    nixpkgs.url = "github:jordanisaacs/nixpkgs/brc-kinds";
    crate2nix = {
      url = "github:jordanisaacs/crate2nix/kinds";
      flake = false;
    };
    rust-overlay.url = "github:oxalica/rust-overlay";
    neovim-flake.url = "github:jordanisaacs/neovim-flake";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    neovim-flake,
    crate2nix,
    ...
  }: let
    system = "x86_64-linux";
    overlays = [
      rust-overlay.overlays.default
      (self: super: let
        rust = super.rust-bin.stable.latest.default;
      in {
        rustc = rust;
        cargo = rust;
        clippy = rust;
      })
    ];

    # Build crate2nix with default rustc
    pkgs = import nixpkgs {
      inherit system overlays;
    };

    neovim = neovim-flake.lib.neovimConfiguration {
      inherit pkgs;
      modules = [
        {
          config = {
            vim.lsp = {
              enable = true;
              lightbulb.enable = true;
              lspSignature.enable = true;
              nvimCodeActionMenu.enable = true;
              trouble.enable = true;
              formatOnSave = true;
              rust = {
                enable = true;
                rustAnalyzerOpts = "";
              };
              nix.enable = true;
            };
            vim.statusline.lualine = {
              enable = true;
              theme = "onedark";
            };
            vim.visuals = {
              enable = true;
              nvimWebDevicons.enable = true;
              lspkind.enable = true;
              indentBlankline = {
                enable = true;
                fillChar = "";
                eolChar = "";
                showCurrContext = true;
              };
              cursorWordline = {
                enable = true;
                lineTimeout = 0;
              };
            };

            vim.theme = {
              enable = true;
              name = "onedark";
              style = "darker";
            };
            vim.autopairs.enable = true;
            vim.autocomplete = {
              enable = true;
              type = "nvim-cmp";
            };
            vim.filetree.nvimTreeLua.enable = true;
            vim.tabline.nvimBufferline.enable = true;
            vim.telescope = {
              enable = true;
            };
            vim.markdown = {
              enable = true;
              glow.enable = true;
            };
            vim.treesitter = {
              enable = true;
              autotagHtml = true;
              context.enable = true;
            };
            vim.keys = {
              enable = true;
              whichKey.enable = true;
            };
            vim.git = {
              enable = true;
              gitsigns.enable = true;
            };
          };
        }
      ];
    };

    nativeBuildInputs = with pkgs; [
      rustc

      neovim.neovim

      # cargo-edit
      # cargo-audit
      # cargo-tarpaulin
      # clippy
      crate2nix-pkgs
    ];

    crate2nix-pkgs = import crate2nix {inherit pkgs;};

    rustix-uring = let
      generated = (pkgs.callPackage ./Cargo.nix {}).workspaceMembers;
    in {
      io-uring-test = generated.io-uring-test.build;
      io-uring-test-ci = generated.io-uring-test.build.override {features = ["ci"];};
      rustix-uring-dev = generated.rustix-uring.build.override {buildKinds = ["lib" "test" "example"];};
      io-uring-bench = generated.io-uring-bench.build.override {buildKinds = ["bench"];};
    };
  in {
    packages.${system} = rustix-uring;
    devShells.${system}.default = pkgs.mkShell {
      inherit nativeBuildInputs;
    };
  };
}
