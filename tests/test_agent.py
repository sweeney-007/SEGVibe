"""The agentic loop with a scripted model that answers each kind of prompt."""
from __future__ import annotations

import json

from segvibe.agent.graph import Budget, run_agent
from segvibe.check import CheckConfig
from segvibe.gen.models import Scripted
from segvibe.task import load_tasks

FAST = CheckConfig(fuzz_seeds=1, fuzz_iters=50, perf=False)


def scripted(replies: dict[str, list[str]]):
    """Route each prompt to a reply list by the phrase that identifies the step."""
    keys = {"design plan (at most": "plan", "Implement the plan": "implement", "Find the root cause": "fix",
            "senior C reviewer": "review", "targeted test": "probe", "Refactor only": "refine"}
    seen: dict[str, int] = {}

    def fn(messages):
        user = messages[-1]["content"]
        step = next(v for k, v in keys.items() if k in user)
        i = seen.get(step, 0)
        seen[step] = i + 1
        rs = replies[step]
        return rs[min(i, len(rs) - 1)]
    return Scripted(fn=fn)


def c(code):
    return f"```c\n{code}```"


def test_agent_fixes_probes_and_refines():
    t = load_tasks(["reverse_words"])[0]
    buggy = t.reference.replace("malloc(n + 1)", "malloc(n)")
    # correct, but with one long function -> refine splits it; behaviour must stay identical
    refactored = t.reference.replace("char *reverse_words(const char *s) {", """static size_t skip_back(const char *s, size_t i, int space) {
      while (i > 0 && (s[i - 1] == ' ') == space) i--;
      return i;
  }

  char *reverse_words(const char *s) {""").replace(
        "while (i > 0 && s[i - 1] == ' ') i--;", "i = skip_back(s, i, 1);").replace(
        "while (i > 0 && s[i - 1] != ' ') i--;", "i = skip_back(s, i, 0);")
    review = json.dumps({"design_issues": [{"line": 4, "issue": "two near-identical scan loops", "fix": "helper"}],
                         "suspected_problems": [
                             {"category": "vuln", "problem": "string of only spaces", "trigger": "\"     \""},
                             {"category": "bug", "problem": "wrong expectation", "trigger": "x"}]})
    gen = scripted({
        "plan": ["- scan from the end, copy each word once: O(n)\n- one malloc of n + 1"],
        "implement": [c(buggy)],
        "fix": [c(t.reference)],
        "review": [review, '{"design_issues": [], "suspected_problems": []}'],
        "probe": ['```c probe\nchar *r = reverse_words("     ");\nCHECK_STR(r, "");\nfree(r);\n```',
                  '```c probe\nchar *r = reverse_words("a b");\nCHECK_STR(r, "a b");\nfree(r);\n```'],
        "refine": [c(refactored)],
    })
    events = []
    out = run_agent(t, gen, FAST, Budget(steps=8), on_event=events.append)
    acts = [(e["action"], e["outcome"]) for e in events]
    assert ("analyze", "accepted") in acts                      # buggy draft analysed
    assert out["best"]["report"].clean                          # fixed
    assert ("probe", "dismissed") in acts                       # both probes dismissed:
    notes = " ".join(e["note"] for e in events if e["action"] == "probe")
    assert "code handles it" in notes and "reference fails it" in notes   # second probe was a wrong test
    assert not out["probes"]
    assert out["best"]["code"].count("skip_back") >= 3          # refactor accepted
    assert out["best"]["design"].penalty <= 0.0
    assert out["stop_reason"]


def test_agent_rejects_regressions_and_confirms_real_problems():
    t = load_tasks(["is_balanced"])[0]
    fixed_stack = t.variants[0].code                            # passes the tests? no: deep nesting overflows
    small = t.reference
    review = json.dumps({"design_issues": [], "suspected_problems": [
        {"category": "vuln", "problem": "very deep nesting", "trigger": "100000 '(' then ')'"}]})
    gen = scripted({
        "plan": ["- stack"],
        "implement": [c(small)],
        "fix": [c(small)],
        "review": [review, '{"design_issues": [], "suspected_problems": []}'],
        "probe": ['```c probe\nCHECK_INT(is_balanced("(("), 0);\n```'],
        "refine": [c(fixed_stack)],                             # a "refactor" that breaks safety
    })
    events = []
    out = run_agent(t, gen, FAST, Budget(steps=6, refines=1), on_event=events.append)
    rejected = [e for e in events if e["outcome"] == "rejected"]
    assert rejected and "refine" in rejected[0]["note"]
    assert out["best"]["code"] == small and out["best"]["report"].clean


def test_unchanged_fix_is_resampled():
    """A model that hands back the code unchanged gets one sampled retry instead of a wasted check."""
    t = load_tasks(["reverse_words"])[0]
    buggy = t.reference.replace("malloc(n + 1)", "malloc(n)")
    gen = scripted({
        "plan": ["- one pass"],
        "implement": [c(buggy)],
        "fix": [c(buggy), c(t.reference)],      # greedy: unchanged; sampled: the fix
        "review": ['{"design_issues": [], "suspected_problems": []}'],
        "probe": ["```c probe\n```"],
        "refine": [c(t.reference)],
    })
    events = []
    out = run_agent(t, gen, FAST, Budget(steps=4), on_event=events.append)
    assert any(e["action"] == "fix" and e["outcome"] == "unchanged" for e in events)
    assert 0.8 in gen.temps
    assert out["best"]["report"].clean
