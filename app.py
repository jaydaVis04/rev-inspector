from revinspector.cli import main

try:
    from web.app import app
except ImportError:
    app = None


if __name__ == "__main__":
    raise SystemExit(main())
