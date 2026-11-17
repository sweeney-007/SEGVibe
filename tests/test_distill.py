from segvibe.distill.core import (Sample, as_reply, code_hash, pass_at_k, select_examples, split_tasks,
                                  summarize)


def test_split_is_deterministic_and_disjoint():
    ids = [f"t{i:02d}" for i in range(17)]
    train, held = split_tasks(list(reversed(ids)))
    assert held == ["t00", "t03", "t06", "t09", "t12", "t15"]
    assert not set(train) & set(held) and len(train) + len(held) == 17


def test_pass_at_k():
    assert pass_at_k(10, 0, 1) == 0.0
    assert pass_at_k(10, 10, 1) == 1.0
    assert abs(pass_at_k(10, 3, 1) - 0.3) < 1e-12
    assert pass_at_k(4, 1, 4) == 1.0


def test_hash_ignores_comments_and_whitespace():
    assert code_hash("int f(){return 1;} // x") == code_hash("int f() {\n  /* y */ return 1;\n}")
    assert code_hash("int f(){return 1;}") != code_hash("int f(){return 2;}")


def test_select_prefers_plain_dedupes_and_caps():
    s = lambda code, src="plain", clean=True, task="a": Sample(task, code, clean, clean, True, src)
    picked = select_examples([s("x=2;", "hinted"), s("x=1;"), s("x = 1 ;"), s("x=3;", clean=False),
                              s("x=4;"), s("x=5;"), s("x=6;")], per_task=3)
    assert [p.code for p in picked] == ["x=1;", "x=4;", "x=5;"]
    seen = {code_hash("x=1;")}
    assert [p.code for p in select_examples([s("x=1;"), s("x=7;")], seen=seen)] == ["x=7;"]


def test_summarize_and_reply():
    ss = [Sample("a", "x=1;", True, True, True), Sample("a", "x=1;", False, True, True),
          Sample("b", "y", False, False, False), Sample("b", "z", False, False, True)]
    m = summarize(ss, ks=(1, 2))
    assert m["tasks"]["a"]["pass@1"] == 1.0 and m["tasks"]["a"]["clean@1"] == 0.5
    assert m["tasks"]["a"]["distinct"] == 0.5 and m["mean"]["pass@1"] == 0.5
    assert as_reply("int x;\n") == "```c\nint x;\n```"
