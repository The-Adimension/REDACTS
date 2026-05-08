"""Contract-driven ``flake.nix`` renderer.

Pins ``nixpkgs`` to the exact commit declared in
``[runtime.nix].nixpkgs_rev`` of the active contract so the Nix
runtime is reproducible across hosts.
"""

from __future__ import annotations

import re
from pathlib import Path

from static.core.contract import FrozenCaseContract


_REV_RE = re.compile(r"^[0-9a-f]{40}$")


def render_flake(contract: FrozenCaseContract) -> str:
    """Render a pinned flake.nix from the contract."""
    nix = contract.nix
    rev = nix.nixpkgs_rev.strip().lower()
    if not _REV_RE.match(rev):
        raise ValueError(
            "Contract [runtime.nix].nixpkgs_rev must be a full 40-hex commit "
            f"SHA (got {nix.nixpkgs_rev!r})."
        )

    return f"""\
# Managed by REDACTS Nix renderer.
# Source: dynamic.nix_render.render_flake
# nixpkgs is pinned via [runtime.nix].nixpkgs_rev in case.toml.
{{
  description = "REDACTS DAST local Nix runtime (contract-pinned)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/{rev}";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = {{ self, nixpkgs, flake-utils }}:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {{ inherit system; }};

        pythonEnv = pkgs.python312.withPackages (ps: with ps; [
          pip
          playwright
          pytest
          pytest-asyncio
          pytest-json-report
          requests
        ]);

        phpEnv = pkgs.{nix.php_attr}.buildEnv {{
          extensions = ({{ enabled, all }}: enabled ++ [
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
        }};

        redactsDastNix = pkgs.writeShellApplication {{
          name = "redacts-dast-nix";
          runtimeInputs = [ pythonEnv phpEnv pkgs.{nix.mariadb_attr} pkgs.{nix.chromium_attr} pkgs.rsync pkgs.unzip ];
          text = ''
            export REDACTS_DAST_NIX_ACTIVE=1
            export PYTHONPATH="$(pwd)''${{PYTHONPATH:+:$PYTHONPATH}}"
            export PLAYWRIGHT_CHROMIUM_EXECUTABLE="${{pkgs.{nix.chromium_attr}}}/bin/chromium"
            exec ${{pythonEnv}}/bin/python -m dynamic.__main__ --runtime nix "$@"
          '';
        }};

        dastShell = pkgs.mkShell {{
          packages = [ pythonEnv phpEnv pkgs.{nix.mariadb_attr} pkgs.{nix.chromium_attr} pkgs.rsync pkgs.unzip ];
          shellHook = ''
            export REDACTS_DAST_NIX_ACTIVE=1
            export PYTHONPATH="$PWD''${{PYTHONPATH:+:$PYTHONPATH}}"
            export PLAYWRIGHT_CHROMIUM_EXECUTABLE="${{pkgs.{nix.chromium_attr}}}/bin/chromium"
          '';
        }};
      in {{
        devShells = {{
          default = dastShell;
          dast = dastShell;
        }};

        apps = {{
          default = {{
            type = "app";
            program = "${{redactsDastNix}}/bin/redacts-dast-nix";
          }};
          "redacts-dast-nix" = {{
            type = "app";
            program = "${{redactsDastNix}}/bin/redacts-dast-nix";
          }};
        }};

        packages."redacts-dast-nix" = redactsDastNix;
      }}
    );
}}
"""


def render_to_path(contract: FrozenCaseContract, target_path: Path) -> Path:
    """Render flake.nix to ``target_path`` (parent created if missing)."""
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target_path.write_text(render_flake(contract), encoding="utf-8")
    return target_path
