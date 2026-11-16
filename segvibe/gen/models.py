"""Code generators behind one interface: messages in, text out.

    hf:Qwen/Qwen2.5-Coder-1.5B-Instruct   local, CPU (pip extra "local")
    groq:llama-3.3-70b-versatile          any LangChain provider, key in .env (extra "api")
    scripted                              canned replies, for tests
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field


@dataclass
class Generation:
    text: str
    seconds: float
    tokens: int = 0


class Generator:
    name = "base"

    def generate(self, messages: list[dict], temperature: float = 0.0) -> Generation:
        """temperature 0 = greedy (the default, reproducible); > 0 samples, used to get a different
        answer when the greedy one was already tried."""
        raise NotImplementedError


@dataclass
class Scripted(Generator):
    """Returns the given replies in order (the last one repeats)."""
    replies: list[str] = field(default_factory=list)
    name: str = "scripted"
    calls: list[list[dict]] = field(default_factory=list)
    fn: object = None   # optional callable(messages) -> str, used instead of `replies`
    temps: list[float] = field(default_factory=list)

    def generate(self, messages, temperature=0.0):
        self.calls.append(messages)
        self.temps.append(temperature)
        if self.fn:
            return Generation(self.fn(messages), 0.0)
        i = min(len(self.calls) - 1, len(self.replies) - 1)
        return Generation(self.replies[i], 0.0)


class HFLocal(Generator):
    """A Hugging Face chat model on CPU. Greedy by default; seeded sampling when temperature > 0."""

    def __init__(self, model_id: str, max_new_tokens: int = 1200):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        torch.set_num_threads(os.cpu_count() or 4)
        self.name = model_id.split("/")[-1]
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, torch_dtype=torch.float32)
        self.model.eval()
        self.max_new_tokens = max_new_tokens
        self.torch = torch

    def generate(self, messages, temperature=0.0):
        t0 = time.time()
        ids = self.tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt")
        sampling = {"do_sample": False}
        if temperature > 0:
            self.torch.manual_seed(0)
            sampling = {"do_sample": True, "temperature": temperature, "top_p": 0.95}
        with self.torch.no_grad():
            out = self.model.generate(ids, max_new_tokens=self.max_new_tokens, **sampling,
                                      attention_mask=self.torch.ones_like(ids),
                                      pad_token_id=self.tok.eos_token_id)
        new = out[0, ids.shape[1]:]
        return Generation(self.tok.decode(new, skip_special_tokens=True), time.time() - t0, len(new))


class LangChainChat(Generator):
    """Any provider LangChain's init_chat_model knows ("groq:...", "openai:...", "anthropic:...")."""

    def __init__(self, spec: str):
        from dotenv import load_dotenv
        from langchain.chat_models import init_chat_model

        load_dotenv()
        self.name = spec
        self.spec, self.init = spec, init_chat_model
        self.llm = init_chat_model(spec, temperature=0, max_retries=3, timeout=120)

    def generate(self, messages, temperature=0.0):
        t0 = time.time()
        llm = self.llm if temperature <= 0 else self.init(self.spec, temperature=temperature,
                                                           max_retries=3, timeout=120)
        msg = llm.invoke([(m["role"], m["content"]) for m in messages])
        usage = getattr(msg, "usage_metadata", None) or {}
        return Generation(str(msg.content), time.time() - t0, usage.get("output_tokens", 0))


def make_generator(spec: str) -> Generator:
    if spec.startswith("hf:"):
        return HFLocal(spec[3:])
    return LangChainChat(spec)
