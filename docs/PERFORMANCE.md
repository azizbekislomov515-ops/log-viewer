# Performance

## Targets

| What | Target | 0.1.0 |
|---|---|---|
| Start to first window | < 2 s | **0.58 s** (median, dev install) |
| Live ingestion into an open tab | 20,000 lines/s, UI responsive | p99 frame < 100 ms (`tests/test_gui_stress.py`) |
| Views | smooth with 1M+ rows | virtualized model, ids only per row |
| Explaining a line | fast enough for every visible row | 4-40 µs per line, 224 rules (`tests/test_explain_bench.py`) |
| Redaction | must not slow ingestion | 8-18 µs per line |

## How it is measured

```sh
uv run python tools/perf.py startup --runs 7   # fresh process, empty config, offscreen
uv run python tools/perf.py memory             # RSS: 10 s idle with real discovery,
                                               # 10 s of the demo at 20,000 lines/s
uv run pytest -m perf -s                       # stress and load tests with their numbers
```

Startup is measured from process start until the main window has painted its first frame
(`QTimer.singleShot(0)` after `showEvent`). Every run uses empty XDG directories, so it
includes creating the database.

## Phase 9 pass: before and after

Measured on the same machine, same settings (Python 3.13 dev environment, offscreen,
7 runs; memory is the median of 3).

| | Before | After |
|---|---|---|
| Start to first frame (median) | 0.91 s | **0.58 s** (-36%) |
| Loading the 8 rule packs | 653 ms | **218 ms** (-67%) |
| RSS after 10 s idle | 138 MB | 145 MB |
| RSS after 10 s at 20,000 lines/s | 177 MB | 181 MB |

### Hotspots fixed

1. **Rule packs were parsed twice, in pure Python.** Each pack was read once with
   `yaml.compose` (for line numbers in error messages) and again with `yaml.safe_load`
   (for the data), both with the pure-Python loader. That was about 60% of startup in
   the profile. Now each pack is composed once with libyaml (`CSafeLoader`), and the data
   is built from the same node tree.
2. **Every template was parsed twice.** It was parsed for the safety checks, then
   `from_string(source)` parsed it again. Now the already-checked syntax tree is compiled.
3. **The first frame waited for the rules.** The GUI's explanation engine was built in
   the window constructor. It now loads on a worker thread while the window is built; the
   first explanation request waits for it if needed (it rarely is). The analytics thread
   now shares this engine instead of building a second one.

### Memory

About 61 MB of the idle size is Qt itself (a bare Qt window). LogLens's own working set
is bounded: queue and ring buffers in the pipeline, at most 5 M row ids per view, a 20,000
entry page cache, and the memory governor (default budget 1 GB), which sheds caches and
old loaded rows when the budget is exceeded.

Moving the rules to a worker thread costs about 7 MB of RSS. glibc gives the thread its
own malloc arena. This was kept for the faster start. Set `MALLOC_ARENA_MAX=2` in the
environment to trade a little speed for that memory.

## The packaged build

The `.deb` and AppImage byte-compile everything at build time (nothing is compiled or
written under `/opt` at run time) and keep only the Qt modules and plugins LogLens loads.
That makes them 53 MB to download and 232 MB installed.
