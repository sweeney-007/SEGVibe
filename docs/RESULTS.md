# Results

All numbers from an Intel i5-9600K iMac, CPU only. Model: Qwen2.5-Coder-1.5B-Instruct (local, greedy).

## 1. Detection: which layer catches which defect

`scripts/eval_detect.py`: 17 reference solutions plus 95 defects (28 hand-written flawed versions, 67
automatic mutations of the references: dropped `free`/`fclose`, allocations one byte short, `<` -> `<=`
in loops, removed NULL checks, flipped comparisons). Caught = any finding of medium or high severity.

| Expected | n | caught | right category |
|---|---|---|---|
| bug | 8 | 100% | 100% |
| leak | 24 | 96% | 96% |
| overuse | 9 | 100% | 100% |
| vuln | 41 | 85% | 78% |
| crash | 13 | 100% | 100% |
| **all** | **95** | **93%** | **89%** |

False positives: **0 of 17** references flagged.

| Layer | catches | caught by it alone |
|---|---|---|
| static: compiler + Clang Static Analyzer | 35% | 0 |
| AST rules (tree-sitter) | 13% | 0 |
| hidden tests + ASan/UBSan | 43% | 30 |
| fuzzing under sanitizers | 2% | 2 |
| leak / heap tracker | 15% | 1 |
| allocation-failure runs | 36% | 4 |
| time and memory profile | 8% | 5 |

- **No single layer is enough.** Tests with sanitizers catch the most, but 12 defects were caught
  by a single other layer alone. Five were caught only by the time and memory profile: quadratic string
  building and memory spikes that pass every test. Four were caught only by making allocations fail:
  leaks and crashes on out-of-memory paths that normal runs never take.
- **Static analysis is broad but not decisive.** It flags a third of the defects, nearly always
  together with a runtime check. Its value is the exact line and path it reports, which goes into
  the repair prompt.
- **Misses (7).** Most are equivalent or near-equivalent mutants that no check can see:
  - a stack sized `n` where `n` is enough (`is_balanced`);
  - a removed `free` in a branch that never runs (`most_frequent_word`, the `if (!best)` guard);
  - a loop that now also reads the string's terminating NUL, which is harmless (`most_frequent_word`,
    line 27; an earlier run "caught" it only through a spurious analyzer warning, see below);
  - loops that read or free one slot past the data but inside a larger buffer, or a slot that is
    always NULL (`most_frequent_word` line 36, `read_lines`, `split_words`): ASan sees no error, and
    MemorySanitizer, which would see an uninitialized read, does not run on macOS.
- **Run-to-run changes.** Perf runs now get a fixed 1 MB stack. The input size is chosen by timing, so
  with the default 8 MB stack a recursive `list_free` overflowed on one machine and not on another
  (it passed on the Linux CI runner). The `most_frequent_word` reference also gained an `if (!best)`
  guard, because newer Clang analyzers flag a null dereference they cannot rule out. That warning was
  what had "caught" the line-27 mutant before; the previous run reported 95% of 94.
- **Vulnerabilities in the wrong category (78% vs 88%).** Off-by-one mutants often show up first as
  wrong results or analyzer warnings rather than as an overflow. They are still caught.

## 2. Retrieval: does each stage bring better fix guidance?

`scripts/eval_retrieval.py`. Queries are the real findings from section 1 (89 defect cases). The
knowledge base has 1,011 documents: 984 MITRE CWE weaknesses, 27 fix recipes, and repair memory when
runs exist. A document is relevant when it is a recipe for the finding's kind, or the CWE entry for
its CWE or a direct parent or child.

| Configuration | queries | hit@3 | recipe@3 | MRR@10 | findings covered in prompt | ms/case |
|---|---|---|---|---|---|---|
| BM25 only, raw query | 175 | 0.73 | 0.44 | 0.54 | 0.66 | 10 |
| dense only (bge-small), raw | 175 | 0.79 | 0.40 | 0.67 | 0.73 | 101 |
| hybrid BM25 + dense (RRF), raw | 175 | 0.87 | 0.51 | 0.70 | 0.81 | 82 |
| + pre-retrieval (expansion, CWE name, API terms) | 175 | 0.97 | 0.45 | 0.89 | 0.94 | 108 |
| + filter (deprecated, non-C CWEs) | 175 | 0.97 | 0.45 | 0.89 | 0.94 | 101 |
| + scoring (CWE / kind / API boosts) | 175 | 0.97 | 0.94 | 0.97 | 0.94 | 108 |
| + grouping findings (query-side clustering) | **117** | 1.00 | 0.99 | 1.00 | 0.94 | 71 |
| + candidate clustering (**full default**) | 117 | 1.00 | 0.99 | 1.00 | 0.94 | 82 |
| full + cross-encoder rerank | 117 | 0.91 | 0.44 | 0.89 | 0.78 | 4,566 |
| full − pre-retrieval | 117 | 0.80 | 0.49 | 0.69 | 0.66 | 95 |
| full − dense | 117 | 1.00 | 0.99 | 1.00 | 0.94 | **22** |
| full − BM25 | 117 | 1.00 | 0.99 | 1.00 | 0.94 | 78 |
| full − scoring | 117 | 0.99 | 0.52 | 0.93 | 0.93 | 96 |

What each stage adds:

| Stage | Verdict |
|---|---|
| **Pre-retrieval** (normalise sanitizer text, expand the defect kind into plain words, add the CWE id and name, pull API names such as `strcat` and `realloc` from the offending line) | **Biggest gain.** Coverage 0.81 -> 0.94, MRR 0.70 -> 0.89. Removing it from the full pipeline costs the most (coverage 0.94 -> 0.66). Sanitizer messages are short and full of addresses; the checker knows more than its text says. |
| **Hybrid retrieval** | Helps raw queries (BM25 0.73 / dense 0.79 -> hybrid 0.87 hit@3). Once queries are expanded, either retriever alone matches the hybrid. **BM25 alone is the efficient choice: same quality at 22 ms instead of 82 ms.** |
| **Filtering** | **No effect.** Deprecated and non-C CWEs never ranked high for these queries. Kept because it is free and protects other inputs. |
| **Scoring boosts** | Put a fix recipe in the top 3 (0.45 -> 0.94). Partly by construction: the boost and the relevance label both use the checker's defect kind. That kind is real information the checker has, so using it is legitimate. Whether recipes help the *repair* is decided in section 3. |
| **Grouping findings** (clustering on the query side) | Same coverage from **33% fewer queries**, 17% less prompt text, lower latency. Five findings about one `strcat` line are one problem. |
| **Candidate clustering** (agglomerative, post-retrieval) | **No effect.** With two documents per query group and grouped queries, the top results are already diverse. |
| **Cross-encoder rerank** (ms-marco MiniLM) | **Harmful.** Recipe@3 0.99 -> 0.44, coverage 0.94 -> 0.78, 55x slower. A web-search reranker prefers long CWE prose over short, actionable recipes. Off by default. |

## 3. Does retrieval make repairs succeed more often?

`scripts/eval_repair_rag.py --configs none full`: 40 defects sampled (seed 0) from the 89 the checker
caught. For each, the model gets the flawed code and the checker's findings and makes **one** repair
attempt. The only difference between the two runs is the retrieved guidance in the prompt. Fixed = tests
pass and no high-severity finding. Qwen2.5-Coder-1.5B, greedy, about 3.5 minutes per attempt on CPU.

| Configuration | fixed | tests pass | does not compile |
|---|---|---|---|
| no guidance | 8 / 40 (20%) | 15 / 40 (38%) | 15 |
| full retrieval pipeline | **13 / 40 (32%)** | **20 / 40 (50%)** | 13 |

| Expected category | n | fixed, no guidance | fixed, with retrieval |
|---|---|---|---|
| leak | 11 | 3 | 5 |
| vuln | 16 | 3 | 4 |
| crash | 6 | 2 | 3 |
| overuse | 5 | 0 | 1 |
| bug | 2 | 0 | 0 |

- **Paired: retrieval fixed 7 defects that the plain prompt did not, and lost 2.** The other 31 came out
  the same. The wins are mostly ownership and size problems where a recipe states the exact rule: free
  on every path (`R-cleanup-goto`, `R-ownership`), allocate `len + 1` (`R-string-size`), check the size
  before allocating (`R-untrusted-size` for the `rle_decode` variant).
- **The effect is not statistically established.** 7 wins against 2 losses gives p ≈ 0.18 (two-sided
  sign test). The direction is consistent across categories, but 40 one-shot repairs by a 1.5B model are
  too few to rule out chance. Both losses were the model breaking code that it fixed without guidance
  (one compile error, one crash), which is the noise a small greedy model shows when its prompt changes.
- **The model is the bottleneck, not the guidance.** A third of all repairs do not compile in either
  configuration. The repair loop (`segvibe solve`, several rounds) and the agent hide much of this by
  feeding the compiler errors back.
- **Verdict:** retrieval is worth turning on for repairs (`--rag`). This run used the full default
  pipeline (hybrid BM25 + dense, pre-retrieval, filter, scoring, grouping, candidate clustering). It
  costs about 0.1 s per repair, which is nothing next to a 3-minute generation, and the measured
  direction is positive. The stages that showed no effect in section 2 (dense
  retrieval, filter, candidate clustering) were not tested here separately, so there is no repair-level
  evidence for them either way.

## 4. Agentic loop

`segvibe agent --task T --model hf:Qwen/Qwen2.5-Coder-1.5B-Instruct --rag` on two tasks, default budget
(10 steps, stop after 3 rejected versions in a row). About 2–3 minutes per model call on CPU.

| Task | First version | Fix attempts | Result |
|---|---|---|---|
| `is_balanced` | 10/11 tests: `is_balanced(NULL)` returns -1, the requirement says 0 | 3 rejected (one introduced a heap overflow) | stopped, best = first version |
| `url_decode` | heap overflow: the `'+'` branch never advances `i` | 3 rejected | stopped, best = first version |

**The loop works; this model is too weak to drive it.** Neither run got past the fix step, so review,
probe and refine never ran with the real model. Those steps are covered only by the scripted tests in
`tests/test_agent.py`. What the runs did show:

- **The regression guard does its job.** A fix that turned a wrong return value into a heap overflow
  was rejected, and the best version stayed the one with the smaller problem.
- **Small models echo their input.** Asked to fix code, the 1.5B model often returned it unchanged. With
  greedy decoding every retry was identical, so the first runs spent three rounds checking the same code.
  The agent now resamples once (temperature 0.8) when a fix comes back unchanged; in the runs above that
  produced different code, but not a correct fix.
- **Better feedback was not enough.** Sanitizer findings now quote the hidden test that triggered them
  (for `url_decode`: `r = url_decode("x+y");`). The model still did not find the missing `i++`.

A stronger model (`--model groq:llama-3.3-70b-versatile`, or a 7B+ coder model on a GPU) is needed to
show the review, probe and refine steps on real output. Logs: `runs/agent_*.log`.

## 5. On-policy self-distillation: stopped at the data-collection step

The idea: the model samples solutions, the checker keeps the clean ones, failing samples get one repair
attempt with the checker's findings as hints, and the clean results are used to fine-tune the model
(LoRA) on the **plain** prompt. The model learns to write, without hints, what it wrote with them. Then
repeat with the new model. Code: `segvibe/distill/core.py` (selection, metrics; tested in
`tests/test_distill.py`) and `scripts/distill_modal.py` (vLLM sampling and LoRA training on an NVIDIA L4,
checks in parallel CPU containers on Ubuntu 24.04 + clang 18, the CI toolchain). Split: 11 training
tasks, 6 held out (every third task by id).

The pipeline ran end to end: all 17 references pass the cloud checker, sampling, checking and the
hinted repairs worked. But the base model, Qwen2.5-Coder-1.5B-Instruct sampled at temperature 0.8,
produced almost no clean code to learn from:

| Run | Samples | Compiled | Tests pass | Clean |
|---|---|---|---|---|
| all 17 tasks, 4 samples each (checked locally) | 68 | 45 | 5 | **2** (one task) |
| round 1, training tasks, 4 samples each | 44 | | | **4** (one task) |
| round 1, hinted repairs of the failing samples | 40 | | | **0** |
| held-out tasks, 4 samples each | 24 | 58% | 0 | 0 |

First finding per sample (68 samples): compile error 23, heap buffer overflow 11, memory leak 7, wrong
result 6, then SEGV, global buffer overflow and timeouts. Samples that included a `main()` despite the
prompt were not the problem: removing it changed one compile result and no test outcome.

- **Verdict: self-distillation needs a base model that already succeeds sometimes.** With 2–4 clean
  samples out of 44–68, all on one task, the training set would teach one task and nothing else. The run
  was stopped there rather than spend GPU time fine-tuning on it.
- **What would make it work:** a stronger base model, such as Qwen2.5-Coder-7B-Instruct (fits an L4 for
  sampling; LoRA training would likely need 4-bit QLoRA), and a larger task set than 17.
- **A checker bug the samples found:** a generated program printed bytes that are not valid UTF-8, and
  reading its output crashed the checker. Program output is now decoded with replacement characters.
