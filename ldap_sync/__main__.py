"""CLI entry point: ldap-sync --config config.yaml [--dry-run]."""

from __future__ import annotations

import argparse
import logging
import sys

from .config import load_config
from .sync import run


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ldap-sync", description=__doc__)
    p.add_argument("--config", required=True, help="path to YAML config")
    p.add_argument("--dry-run", action="store_true", help="log planned actions, make no changes")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config)
    return run(cfg, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
