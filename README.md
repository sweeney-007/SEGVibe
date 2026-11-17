# SEGVibe

**Requirement in, checked C code out.** SEGVibe asks a code LLM to write C
from a plain-language requirement. It then puts the code through the
checks a careful reviewer would run, feeds what they find back to the
model and repeats until the code is clean:

- **bugs:** hidden tests, plus UndefinedBehaviorSanitizer for signed
  overflow, bad shifts and other undefined behaviour
- **memory leaks and unclosed files:** an allocation tracker that names
  the line that allocated the block
- **resource overuse:** time growth measured at n and 4n, peak heap use,
  huge allocations, hangs
- **vulnerabilities:** buffer overflows, use-after-free and double free
  (AddressSanitizer, also on fuzzed input); unbounded copies and format
  strings (static analysis and AST rules)
- **crashes:** NULL dereference, stack overflow, division by zero, and
  crashes when `malloc` fails

The name comes from SIGSEGV, the "segmentation fault" signal, plus "vibe
coding". The point is that generated code can pass its tests and still
segfault, leak or slow to a crawl in production.

## Why this matters

AI assistants now write a large share of new code, and much of the
world's infrastructure is still C and C++. In those languages the
dangerous bugs are the ones tests do not see: around
[70% of serious security bugs in Chromium](https://www.chromium.org/Home/chromium-security/memory-safety/)
are memory-safety problems. A generated function can return the right
answer on every test and still overflow a buffer, leak on an error path or
take quadratic time. SEGVibe asks what it takes to catch those problems
automatically, how much each kind of check contributes, and whether the
findings can teach the model to fix them.

The same ideas run through recent AI research:

- **Verifiers as the source of truth.** Reasoning models such as
  [DeepSeek-R1](https://arxiv.org/abs/2501.12948) are trained with rewards
  that come from checking answers, including running code against tests.
  A layered checker like this one is that kind of verifier, made harder to
  game: code that passes the tests but leaks or overflows still fails.
- **Execution feedback for code agents.**
  [Self-Debug](https://arxiv.org/abs/2304.05128),
  [Reflexion](https://arxiv.org/abs/2303.11366) and
  [AlphaCodium](https://arxiv.org/abs/2401.08500) improve code by feeding
  test results back to the model. SEGVibe feeds back sanitizer, fuzzer,
  analyzer and profiler findings with line numbers, and keeps a regression
  guard so a "fix" cannot make things worse.
- **AI for finding vulnerabilities.** Google's
  [Big Sleep agent found an exploitable bug in SQLite](https://googleprojectzero.blogspot.com/2024/10/from-naptime-to-big-sleep.html),
  [OSS-Fuzz uses LLMs to write fuzz targets](https://security.googleblog.com/2023/08/ai-powered-fuzzing-breaking-bug-hunting.html),
  and DARPA's [AI Cyber Challenge](https://aicyberchallenge.com/) pairs
  LLMs with fuzzers and analyzers to find and patch bugs.
- **Learning from your own verified outputs.**
  [STaR](https://arxiv.org/abs/2203.14465) and
  [ReST](https://arxiv.org/abs/2308.08998) fine-tune a model on its own
  answers that pass a check. SEGVibe includes that loop for C code; with a
  1.5B model it found too few clean samples to learn from, which shows the
  method's main precondition (see the results).

A real agent run with a small local model (Qwen2.5-Coder-1.5B on CPU). It shows the checks and the
regression guard at work, and also that a 1.5B model is too weak to finish the job:

```
$ segvibe agent --task is_balanced --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --rag
plan     done       Design Plan: ...
analyze  accepted   tests 10/11, found: bug        (is_balanced(NULL) == -1, expected 0)
retrieve done       R-edge-cases, CWE-684
fix      unchanged  the model returned the code unchanged; sampling a different answer
analyze  rejected   no improvement: tests 0/0, found: vuln vs best tests 10/11, found: bug
...
stopped: 3 rejected versions in a row; best version 1
```

The second attempt "fixed" the wrong return value by introducing a heap overflow, and the guard kept the
better version. [docs/RESULTS.md](docs/RESULTS.md) section 4 has both runs.

## How it works

Two ways to drive it: a simple **repair loop** (`segvibe solve`: generate, check, fix, repeat) and
an **agent** (`segvibe agent`) that also improves the design and hunts for problems the checks
missed.

### The agent (LangGraph)

```
plan -> implement -> analyze -> decide --> fix -----> analyze      (high-severity findings)
                                  |   --> review ---> decide       (clean code: design + suspicions)
                                  |   --> probe ----> decide       (turn a suspicion into a test)
                                  |   --> refine ---> analyze      (refactor; must stay clean)
                                  +-> stop
```

- **plan**: a short design (algorithm, complexity, ownership, buffer sizes, edge cases) before any code.
- **analyze**: every check below, plus **design metrics** from the AST: function length, cyclomatic
  complexity, nesting depth, parameters, duplicated blocks, magic numbers.
- **review**: the model reviews clean code like a senior C reviewer and lists design issues and
  *suspected problems*, i.e. inputs where the code might still fail.
- **probe**: each suspicion becomes a targeted test. A probe that the reference solution fails is a
  wrong test and is dropped. A probe that breaks the current code is a **confirmed problem**: it is
  kept as a regression test and the agent fixes it.
- **refine**: refactor for the design issues. Accepted only if every check still passes, the design
  penalty does not rise and the code is not slower.
- **Regression guard and memory**: a new version must score at least as well as the best so far,
  otherwise the agent reverts and the reason ("rejected: refine broke the leak check") goes into the
  next prompt. **decide** is a fixed policy rather than an LLM call, so a 1.5B local model can drive
  the loop.

### Retrieval of fix guidance (RAG)

Repair prompts can include guidance retrieved for the findings (`--rag`), from 984 MITRE CWE
entries, 27 hand-written fix recipes and the repairs the system made before:

| Stage | What it does | Kept? |
|---|---|---|
| grouping (query-side clustering) | findings on the same lines or of the same kind become one query | yes: same coverage, 33% fewer queries |
| pre-retrieval | normalise sanitizer text, expand the defect kind, add CWE id and name, pull C API names from the offending line | yes: largest gain |
| retrieval | BM25 + dense (bge-small) with reciprocal rank fusion | BM25 alone matches it after pre-retrieval, 4x faster |
| filter | drop deprecated and non-C CWEs | no measurable effect |
| scoring | boost exact CWE, parent/child CWEs, recipes for the same kind, shared API names | yes: recipes reach the top 3 |
| candidate clustering | agglomerative clustering for diversity | no measurable effect |
| cross-encoder rerank | ms-marco MiniLM | no: hurts quality, 55x slower |

Each stage was measured on its own: [docs/RESULTS.md](docs/RESULTS.md) sections 2 and 3.

### The checks

```
requirement ──► code LLM ──► candidate.c ──► checks ──► clean? ──► done
                   ▲                            │
                   └──── findings + lines ◄─────┘   (up to N repair rounds)
```

| Level | Check | Finds |
|---|---|---|
| Syntax / AST | tree-sitter rules (`segvibe/checks/rules.py`) | `gets`, unbounded `strcpy`/`sprintf`, non-literal format strings, unchecked `malloc`, `p = realloc(p, …)`, `strlen` in a loop condition |
| Static, path-sensitive | compiler warnings, **Clang Static Analyzer**, **cppcheck** if installed (`checks/static.py`) | leaks on some paths, NULL dereference, use-after-free, uninitialized reads, division by zero |
| Dynamic | hidden tests and a fuzz driver, built with **ASan + UBSan** (`checks/runtime.py`) | overflows, use-after-free, double free, signed overflow, wrong results, hangs |
| Resources | allocation tracker (`runtime/segv_track.c`) | leaked blocks and file handles (with the allocating line), peak heap, refused huge allocations |
| Error paths | the tracker makes allocation #k fail, for each k | crashes and leaks on out-of-memory paths |
| Performance | `-O2` build at n and 4n vs. a reference solution (`checks/perf.py`) | O(n²) where O(n) is asked for, memory hogs, deep recursion on big inputs |

The **allocation tracker** exists because LeakSanitizer does not run on
macOS. A force-included header routes `malloc`/`free`/`fopen`/`fclose`
through counting wrappers. That gives leak reports with file and line on
any OS, peak-heap numbers, a cap that stops runaway allocations before they
hurt the machine, and allocation-failure injection.

Severity decides what blocks. *High* findings were observed at run time
or proven by the path-sensitive analyzer, and code is clean only without
them. *Medium* findings are pattern matches and out-of-memory-path
problems: they go back to the model but do not block.

## Benchmark

`tasks/` holds 17 C tasks chosen because generated code tends to get them
subtly wrong: string building, untrusted parsing (`url_decode`,
`rle_decode`, `parse_int`), sizes that can overflow (`repeat_string`,
`two_sum`), ownership (`split_words`, `linked_list`, `read_lines`) and
algorithms where the naive version is quadratic (`unique_ints`,
`window_max`, `most_frequent_word`). Each task has:

- the requirement,
- a reference solution, which must itself pass every check
  (`scripts/validate_tasks.py`, run in CI),
- hidden tests, a fuzz case and a perf driver,
- hand-written flawed variants labelled with the expected category.

### Results

[docs/RESULTS.md](docs/RESULTS.md) has the full tables.

- **Detection:** 93% of 95 injected and hand-written defects are caught (89% in the right category),
  with 0 false positives on the 17 references. 12 defects are caught by a single layer other than
  tests + sanitizers: the time/memory profile, allocation-failure runs, fuzzing, the leak tracker.
- **Retrieval:** query expansion is the stage that matters (fix-guidance coverage 0.81 -> 0.94).
  Hybrid search, filtering and candidate clustering add nothing once queries are expanded, and the
  cross-encoder reranker makes results worse.
- **Repair:** on 40 caught defects, one repair attempt by the 1.5B model fixed 20% without guidance and
  32% with retrieved guidance (7 won, 2 lost). The direction is positive but the sample is too small to
  be conclusive (p ≈ 0.18).
- **Agent:** with the 1.5B local model, neither of two runs got past the fix step; the regression guard
  rejected every worse version. The review, probe and refine steps are tested with a scripted model only.
- **Self-distillation:** a pipeline that fine-tunes the model on its own checker-approved code (plus
  repairs made with the findings as hints) runs end to end on cloud GPUs, but the 1.5B model produced
  only 2 clean samples out of 68, too few to train on. A stronger base model (7B) is needed.

## Run it

Needs `clang` (Xcode command-line tools on macOS, `apt install clang` on
Linux) and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                    # checker only
uv run segvibe tasks
uv run segvibe check my_code.c --task url_decode
uv run pytest -q

uv sync --extra local                      # local code LLM on CPU, no API key
uv run segvibe solve --task url_decode --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct
uv run segvibe new "Return a newly allocated copy of s with every vowel removed; NULL on NULL or allocation failure." \
    --signature "char *strip_vowels(const char *s);" --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --out strip.c

uv sync --extra api && cp .env.example .env  # hosted models; put your key in .env
uv run segvibe solve --task url_decode --model groq:llama-3.3-70b-versatile

uv run segvibe agent --task url_decode --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --rag

uv run python -m segvibe.rag.kb            # download the MITRE CWE catalog (for --rag)
uv run python scripts/eval_detect.py       # which layer catches which defect
uv run python scripts/eval_retrieval.py    # what each retrieval stage adds
uv run python scripts/eval_repair_rag.py --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --configs none full
uv run python scripts/eval_generate.py --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct

modal run scripts/distill_modal.py --seed 0   # self-distillation on Modal GPUs (needs a Modal account)
```

`segvibe new` is the open-ended mode. With no hidden tests, the model also
writes tests and a fuzz case, and everything except the reference timing
comparison runs as usual. Its verdict is only as good as those tests.

## Limits

- C only for now. Python, with Bandit, Semgrep and tracemalloc, is the
  natural next language.
- Timing checks are relative to a reference solution, so a benchmark task
  needs one. Free-form requirements get static analysis, sanitizers and
  leak checks but no complexity check.
- The tracker sees allocations made by the candidate's own code. Memory
  that libc allocates inside (for example `getline`) is outside its view;
  ASan still checks its use.
- 17 tasks is a small benchmark. The numbers show what kinds of errors
  occur and what the loop fixes, not a leaderboard.

## Layout

```
segvibe/
  check.py            runs every check -> Report
  findings.py         categories, CWE ids, severity, feedback text
  checks/             build, static, rules, runtime, perf, design metrics
  runtime/            allocation tracker + harness helpers (C)
  gen/                prompts, model backends, repair loop
  agent/              LangGraph agent: plan, review, probe, fix, refine
  rag/                knowledge base (CWE, recipes, repair memory) and retrieval pipeline
  freeform.py         requirement -> tests + code, no hidden tests
  inject.py           bug injection for the detection eval
  distill/            self-distillation: example selection, pass@k / clean@k, diversity
tasks/*.yaml          benchmark tasks
scripts/              validate_tasks, eval_detect, eval_generate, eval_retrieval, eval_repair_rag,
                      distill_modal (self-distillation on Modal)
```

MIT license.
