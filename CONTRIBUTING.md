# Contributing to LogLens

Thanks for helping. The most valuable contributions are usually **rules**: a log line
that LogLens shows but does not explain, turned into a tested explanation.

## Set up

```sh
git clone <this repository> && cd loglens
uv sync                     # Python 3.12+, all dev tools
uv run pre-commit install   # ruff, mypy, bandit on every commit
uv run loglens --demo       # the app on replayed sample logs
```

The tests need a few system libraries for Qt (offscreen):
`ci/install-system-deps.sh` installs them on Debian/Ubuntu.

## Before you open a pull request

```sh
uv run ruff check src tests tools && uv run ruff format --check src tests tools
uv run mypy                                     # strict
uv run pytest -m "not integration and not perf"
uv run loglens-cli rules lint && uv run loglens-cli rules test
uv run bandit -q -c pyproject.toml -r src
```

`-m integration` needs Docker (with `alpine:latest` pulled; tests never pull) and journal
access. `-m perf` asserts on frame times and memory, so run it on an idle machine.

## Adding or fixing a rule

1. Find the pack in `rules/` (or start one; see [docs/WRITING_RULES.md](docs/WRITING_RULES.md)).
2. Add the rule with at least one **example** (a real line, anonymized) and one
   **counter-example** (a similar line it must not match).
3. `uv run loglens-cli rules test` runs every example. `uv run loglens-cli explain
   --file your.log --source <pack>` shows the result on a whole file.
4. Keep regexes linear: anchor them, avoid nested quantifiers. CI checks long crafted
   lines against every built-in pattern.
5. Every value in `action` must end in `| shquote`. Admins copy-paste those commands.

## Code

- Type hints everywhere; mypy strict must pass. Small modules, no global state.
- Docstrings on public APIs. Structured logging (`log.warning("...", extra={...})`).
- Log content is hostile input. Read the security invariants in `CLAUDE.md` and
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before touching collectors, parsers,
  rendering, storage or exports.
- A bug fix comes with a test that fails without it.
- GUI tests run offscreen with pytest-qt. Never call `exec()` on a dialog in a test; stub
  it or use `open()`.

## Commits

One logical change per commit, [Conventional Commits](https://www.conventionalcommits.org/):
`feat(explain): ...`, `fix(collectors): ...`, `docs: ...`, `test: ...`, `perf: ...`.

## Packaging

With only Docker installed (the Dockerfile runs everything as an unprivileged user):

```sh
docker build --target test .                 # ruff, mypy, bandit and the test suite
docker build --target deb --output dist .    # dist/loglens_<version>_amd64.deb
```

Directly on the machine:

```sh
packaging/deb/build-deb.sh            # dist/loglens_<version>_amd64.deb
packaging/appimage/build-appimage.sh  # dist/LogLens-<version>-x86_64.AppImage
docker run --rm -v "$PWD/dist:/dist" -v "$PWD/packaging/qa:/qa:ro" ubuntu:24.04 bash /qa/qa-deb.sh
```

## Reporting security problems

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
