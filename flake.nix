{
  description = "REDACTS DAST local Nix runtime";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        pythonEnv = pkgs.python312.withPackages (ps: with ps; [
          pip
          playwright
          pytest
          pytest-asyncio
          pytest-json-report
          requests
        ]);

        phpEnv = pkgs.php83.buildEnv {
          extensions = ({ enabled, all }: enabled ++ [
            all.curl
            all.dom
            all.fileinfo
            all.gd
            all.intl
            all.mbstring
            all.mysqli
            all.openssl
            all.session
            all.xml
            all.zip
          ]);
          extraConfig = ''
            memory_limit = 512M
            post_max_size = 128M
            upload_max_filesize = 128M
            max_execution_time = 300
          '';
        };

        redactsDastNix = pkgs.writeShellApplication {
          name = "redacts-dast-nix";
          runtimeInputs = [ pythonEnv phpEnv pkgs.mariadb pkgs.chromium pkgs.rsync pkgs.unzip ];
          text = ''
            export REDACTS_DAST_NIX_ACTIVE=1
            export PYTHONPATH="$(pwd)''${PYTHONPATH:+:$PYTHONPATH}"
            export PLAYWRIGHT_CHROMIUM_EXECUTABLE="${pkgs.chromium}/bin/chromium"
            export REDACTS_DAST_INTERNAL_HOSTS="localhost,127.0.0.1,::1"
            exec ${pythonEnv}/bin/python -m dast.__main__ --runtime nix "$@"
          '';
        };

        dastShell = pkgs.mkShell {
          packages = [ pythonEnv phpEnv pkgs.mariadb pkgs.chromium pkgs.rsync pkgs.unzip ];
          shellHook = ''
            export REDACTS_DAST_NIX_ACTIVE=1
            export PYTHONPATH="$PWD''${PYTHONPATH:+:$PYTHONPATH}"
            export PLAYWRIGHT_CHROMIUM_EXECUTABLE="${pkgs.chromium}/bin/chromium"
            export REDACTS_DAST_INTERNAL_HOSTS="localhost,127.0.0.1,::1"
          '';
        };
      in {
        devShells = {
          default = dastShell;
          dast = dastShell;
        };

        apps = {
          default = {
            type = "app";
            program = "${redactsDastNix}/bin/redacts-dast-nix";
          };
          "redacts-dast-nix" = {
            type = "app";
            program = "${redactsDastNix}/bin/redacts-dast-nix";
          };
        };

        packages."redacts-dast-nix" = redactsDastNix;
      }
    );
}
