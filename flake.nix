{
  inputs = {
    nixpkgs.url = "github:jordanisaacs/nixpkgs/aoc-cli-init";
    rust-overlay.url = "github:oxalica/rust-overlay";
    neovim-flake.url = "github:jordanisaacs/neovim-flake";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    neovim-flake,
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
      })
    ];
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

      cargo
      cargo-edit
      cargo-audit
      cargo-tarpaulin
      clippy
    ];
  in
    with pkgs; {
      devShells.${system}.default = mkShell {
        inherit nativeBuildInputs;
      };
    };
}
