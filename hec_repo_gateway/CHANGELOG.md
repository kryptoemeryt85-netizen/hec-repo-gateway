## 0.2.3
- Reproduce the approved HEC regression runtime dependencies: Python 3.13, pytest 9.1.1, highspy 1.15.1, numpy 2.5.3, Jinja2 3.1.6 and matching pytest dependencies.
- Install yq for the fixed schedule test.
- Create the historical test scratch directory inside the gateway private /data volume before the fixed regression run.
- Keep the runner fixed, shell-free, argument-free and GoodWe WRITE=0.

## 0.2.2
- Run the approved HEC regression with the gateway's Python 3.13 interpreter and pinned pytest 9.1.1, avoiding the non-portable mounted venv executable.
- Keep the regression command fixed, argument-free, shell-free, audited, timed out, and GoodWe WRITE=0.

# 0.2.1

- Fixed approved full HEC runner, no arguments, 300s timeout, captured output and audited result.

# Changelog
## 0.2.0
Ingress-only constrained API, writable HA/AppDaemon mappings, fixed fixture
validation, isolated exact Git operations, and explicit BLOCKED full HEC regression.
