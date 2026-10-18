#!/usr/bin/env python3
"""Run the separately enabled, explicitly scoped notification scheduler."""
from _bootstrap import bootstrap

bootstrap()

from worker.notifications import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
