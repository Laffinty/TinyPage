"""TinyPage CLI entry point."""

import sys


def main():
    """Main CLI entry point."""
    from .cli import cli
    sys.exit(cli())


if __name__ == "__main__":
    main()