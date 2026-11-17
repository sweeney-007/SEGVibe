"""Small on-policy self-distillation on cloud GPUs with Modal (https://modal.com).

    modal run scripts/distill_modal.py --seed 0                 # one full run
    modal run scripts/distill_modal.py --seed 0 --rounds 1      # quick check

Each round the current model (Qwen2.5-Coder-1.5B-Instruct, then its LoRA
fine-tunes) samples k solutions per training task, the checker stack scores
them, every failing sample gets one repair attempt with the checker's
findings as hints, and the clean results become training data paired with
the plain prompt (no hints). See segvibe/distill/core.py.

Evaluation after every round: pass@1, clean@1, pass@4, compile rate and
diversity on held-out tasks (never trained on) and on the training tasks.

Three images: vLLM for sampling (GPU), Transformers + PEFT for LoRA training
(GPU), and Ubuntu 24.04 + clang 18 for the checks (CPU, run in parallel; the
same toolchain as CI). Models are kept in the `segvibe-distill` volume.
Results go to runs/distill_seed<seed>.json.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import modal

ROOT = Path(__file__).resolve().parents[1]
BASE = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
VOL = "/vol"
vol = modal.Volume.from_name("segvibe-distill", create_if_missing=True)

check_image = (
    modal.Image.from_registry("ubuntu:24.04", add_python="3.12")
    .apt_install("clang", "llvm", "cppcheck", "make")
    .pip_install("pyyaml>=6", "tree-sitter>=0.23", "tree-sitter-c>=0.23")
    .add_local_dir(ROOT / "segvibe", "/root/segvibe", ignore=["**/__pycache__/**", "rag/**"])
    .add_local_dir(ROOT / "tasks", "/root/tasks")
)
gen_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("vllm==0.6.3.post1", "transformers==4.46.3")
    .env({"HF_HUB_DISABLE_PROGRESS_BARS": "1", "VLLM_LOGGING_LEVEL": "WARNING"})
)
train_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("torch==2.5.1", "transformers==4.46.3", "peft==0.13.2", "accelerate==1.1.1")
    .env({"HF_HUB_DISABLE_PROGRESS_BARS": "1"})
)
app = modal.App("segvibe-distill")


# ---------------------------------------------------------------------- #
# Checks (CPU, parallel)
# ---------------------------------------------------------------------- #
@app.function(image=check_image, cpu=2, memory=2048, timeout=1800, max_containers=60)
def check_chunk(items: list) -> list:
    """items: [(task_id, code)] -> one result dict per item."""
    sys.path.insert(0, "/root")
    os.environ.setdefault("SEGV_CC", "clang")
    from segvibe.check import check
    from segvibe.task import load_tasks

    tasks = {t.id: t for t in load_tasks(task_dir=Path("/root/tasks"))}
    out = []
    for tid, code in items:
        try:
            r = check(code, tasks[tid])
            out.append({"clean": r.clean, "passed": r.tests_passed, "compiled": r.compiled,
                        "summary": r.summary(), "feedback": r.feedback(code),
                        "categories": sorted(r.categories())})
        except Exception as e:  # a checker crash must not take the run down
            out.append({"clean": False, "passed": False, "compiled": False, "summary": f"checker error: {e}",
                        "feedback": "The code could not be checked.", "categories": ["error"]})
    return out


def check_all(items: list, chunk: int = 4) -> list:
    chunks = [items[i:i + chunk] for i in range(0, len(items), chunk)]
    return [r for res in check_chunk.map(chunks) for r in res]


# ---------------------------------------------------------------------- #
# Sampling (GPU, vLLM)
# ---------------------------------------------------------------------- #
@app.function(image=gen_image, gpu="L4", volumes={VOL: vol}, timeout=3600)
def sample(model: str, requests: list, temperature: float = 0.8, max_tokens: int = 1200) -> list:
    """requests: [(messages, n, seed)] -> list of n completions per request."""
    from vllm import LLM, SamplingParams

    vol.reload()
    llm = LLM(model=model, dtype="bfloat16", max_model_len=4096, gpu_memory_utilization=0.85, seed=0)
    tok = llm.get_tokenizer()
    prompts = [tok.apply_chat_template(m, tokenize=False, add_generation_prompt=True) for m, _, _ in requests]
    params = [SamplingParams(n=n, temperature=temperature, top_p=0.95, max_tokens=max_tokens, seed=seed)
              for _, n, seed in requests]
    outs = llm.generate(prompts, params, use_tqdm=False)
    return [[c.text for c in o.outputs] for o in outs]


# ---------------------------------------------------------------------- #
# LoRA fine-tuning (GPU)
# ---------------------------------------------------------------------- #
@app.function(image=train_image, gpu="L4", volumes={VOL: vol}, timeout=3600)
def train(examples: list, out_dir: str, seed: int = 0, epochs: int = 2, lr: float = 1e-4, rank: int = 16) -> dict:
    """examples: [(messages, reply)]. Fine-tunes the BASE model with LoRA on all of them (loss on the
    reply only), merges the adapter and saves a full model to out_dir."""
    import random

    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.manual_seed(seed)
    random.seed(seed)
    tok = AutoTokenizer.from_pretrained(BASE)
    model = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype=torch.bfloat16).cuda()
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()
    model = get_peft_model(model, LoraConfig(r=rank, lora_alpha=2 * rank, lora_dropout=0.05, task_type="CAUSAL_LM",
                                             target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                                                             "gate_proj", "up_proj", "down_proj"]))
    data = []
    for messages, reply in examples:
        prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
        r_ids = tok(reply + tok.eos_token, add_special_tokens=False)["input_ids"]
        data.append((p_ids + r_ids, [-100] * len(p_ids) + r_ids))
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr, weight_decay=0.0)
    batch, losses = 4, []
    steps = epochs * ((len(data) + batch - 1) // batch)
    sched = torch.optim.lr_scheduler.LambdaLR(opt, lambda s: min(1.0, (s + 1) / 5) * max(0.1, 1 - s / steps))
    model.train()
    t0 = time.time()
    for _ in range(epochs):
        random.shuffle(data)
        for i in range(0, len(data), batch):
            b = data[i:i + batch]
            L = max(len(x) for x, _ in b)
            ids = torch.tensor([x + [tok.pad_token_id] * (L - len(x)) for x, _ in b]).cuda()
            lab = torch.tensor([y + [-100] * (L - len(y)) for _, y in b]).cuda()
            att = torch.tensor([[1] * len(x) + [0] * (L - len(x)) for x, _ in b]).cuda()
            loss = model(input_ids=ids, attention_mask=att, labels=lab).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            losses.append(loss.item())
    merged = model.merge_and_unload()
    merged.save_pretrained(out_dir, safe_serialization=True)
    tok.save_pretrained(out_dir)
    vol.commit()
    k = max(1, len(losses) // 4)
    return {"examples": len(data), "steps": len(losses), "loss_first": sum(losses[:k]) / k,
            "loss_last": sum(losses[-k:]) / k, "seconds": time.time() - t0}


# ---------------------------------------------------------------------- #
# Orchestration (runs locally)
# ---------------------------------------------------------------------- #
def run_samples(model, tasks, ids, n, seed, msgs_fn):
    """Sample n completions per task id, check them all, return core.Sample objects."""
    from segvibe.distill.core import Sample
    from segvibe.gen.prompts import extract_code

    reqs = [(msgs_fn(tasks[t]), n, seed * 1000 + i) for i, t in enumerate(ids)]
    texts = sample.remote(model, reqs)
    items = [(t, extract_code(x)) for t, outs in zip(ids, texts) for x in outs]
    res = check_all(items)
    return [Sample(t, code, r["clean"], r["passed"], r["compiled"], feedback=r["feedback"])
            for (t, code), r in zip(items, res)]


def evaluate(model, tasks, train_ids, held_ids, seed, n_eval, n_train_eval):
    from segvibe.distill.core import plain_messages, summarize

    held = run_samples(model, tasks, held_ids, n_eval, seed + 777, plain_messages)
    tr = run_samples(model, tasks, train_ids, n_train_eval, seed + 555, plain_messages)
    return {"held_out": summarize(held), "train": summarize(tr)}


@app.local_entrypoint()
def main(seed: int = 0, rounds: int = 3, k: int = 8, per_task: int = 4, n_eval: int = 16,
         n_train_eval: int = 8, every: int = 3):
    sys.path.insert(0, str(ROOT))
    from segvibe.distill.core import as_reply, hinted_messages, plain_messages, select_examples, split_tasks
    from segvibe.task import load_tasks

    tasks = {t.id: t for t in load_tasks()}
    train_ids, held_ids = split_tasks(list(tasks), every)
    out = ROOT / "runs" / f"distill_seed{seed}.json"
    out.parent.mkdir(exist_ok=True)
    log = {"seed": seed, "base": BASE, "k": k, "per_task": per_task, "n_eval": n_eval, "train": train_ids,
           "held_out": held_ids, "rounds": []}

    refs = check_all([(t, tasks[t].reference) for t in sorted(tasks)])
    bad = [t for t, r in zip(sorted(tasks), refs) if not r["clean"]]
    print(f"references clean in the cloud checker: {len(tasks) - len(bad)}/{len(tasks)} {bad or ''}", flush=True)
    if bad:
        raise SystemExit("fix the checker image first")

    def show(tag, ev):
        h, t = ev["held_out"]["mean"], ev["train"]["mean"]
        print(f"{tag:8s} held-out pass@1 {h['pass@1']:.3f} clean@1 {h['clean@1']:.3f} clean@4 {h['clean@4']:.3f} "
              f"compile {h['compiled']:.2f} distinct {h['distinct']:.2f} | train pass@1 {t['pass@1']:.3f} "
              f"clean@1 {t['clean@1']:.3f}", flush=True)

    model, data, seen = BASE, [], set()
    ev = evaluate(model, tasks, train_ids, held_ids, seed, n_eval, n_train_eval)
    show("base", ev)
    log["rounds"].append({"round": 0, "model": model, "eval": ev})
    out.write_text(json.dumps(log, indent=1))

    for r in range(1, rounds + 1):
        plain = run_samples(model, tasks, train_ids, k, seed * 100 + r, plain_messages)
        failing = [s for s in plain if not s.clean]
        hinted = []
        if failing:
            from segvibe.distill.core import Sample
            from segvibe.gen.prompts import extract_code

            reqs = [(hinted_messages(tasks[s.task], s.code, s.feedback), 1, seed * 100000 + r * 1000 + i)
                    for i, s in enumerate(failing)]
            texts = sample.remote(model, reqs)
            items = [(s.task, extract_code(x[0])) for s, x in zip(failing, texts)]
            res = check_all(items)
            hinted = [Sample(t, c, q["clean"], q["passed"], q["compiled"], source="hinted")
                      for (t, c), q in zip(items, res)]
        new = select_examples(plain + hinted, per_task, seen)
        data += [(plain_messages(tasks[s.task]), as_reply(s.code), s.task, s.source) for s in new]
        stats = {"plain_clean": sum(s.clean for s in plain), "plain": len(plain),
                 "hinted_clean": sum(s.clean for s in hinted), "hinted": len(hinted),
                 "new_examples": len(new), "new_hinted": sum(s.source == "hinted" for s in new),
                 "dataset": len(data), "tasks_with_data": len({d[2] for d in data})}
        print(f"round {r}: plain clean {stats['plain_clean']}/{stats['plain']}, hinted clean "
              f"{stats['hinted_clean']}/{stats['hinted']}, +{stats['new_examples']} examples "
              f"({stats['new_hinted']} hinted), dataset {stats['dataset']} over {stats['tasks_with_data']} tasks",
              flush=True)
        model = f"{VOL}/models/seed{seed}/round{r}"
        tr = train.remote([(m, rep) for m, rep, _, _ in data], model, seed)
        print(f"         trained on {tr['examples']} examples, loss {tr['loss_first']:.3f} -> {tr['loss_last']:.3f}",
              flush=True)
        ev = evaluate(model, tasks, train_ids, held_ids, seed, n_eval, n_train_eval)
        show(f"round {r}", ev)
        log["rounds"].append({"round": r, "model": model, "collect": stats, "train": tr, "eval": ev,
                              "data_tasks": sorted({d[2] for d in data})})
        out.write_text(json.dumps(log, indent=1))
    print(f"wrote {out}")


@app.local_entrypoint()
def dump(k: int = 4, seed: int = 0, max_tokens: int = 1200):
    """Sample k raw completions per task (one GPU call) and save them for local inspection; no cloud checks."""
    sys.path.insert(0, str(ROOT))
    from segvibe.distill.core import plain_messages
    from segvibe.task import load_tasks

    tasks = load_tasks()
    texts = sample.remote(BASE, [(plain_messages(t), k, seed + i) for i, t in enumerate(tasks)],
                          max_tokens=max_tokens)
    out = ROOT / "runs" / "distill_dump.json"
    out.write_text(json.dumps({t.id: x for t, x in zip(tasks, texts)}, indent=1))
    print(f"wrote {out}")
