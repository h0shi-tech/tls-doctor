"""Module entry point for ``python -m tls_doctor``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
