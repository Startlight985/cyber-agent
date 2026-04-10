"""CyberAgent — routes A2A messages to specialized solvers.

Routing:
  1. Ethernaut Arena → SoliditySolver (stateful, tool-based)
  2. Security Evaluator → MitreDetector (multi-layer pipeline)
  3. RCA-Bench → RcaSolver (crash analysis → loc.json)
  4. Unknown → generic LLM
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from src.llm import call_llm, MODEL_HAIKU

log = logging.getLogger("cyber.agent")


@dataclass
class CyberAgent:
    session_id: str = ""
    history: list[dict] = field(default_factory=list)
    _solidity_solver: Any = field(default=None, repr=False)
    _mitre_detector: Any = field(default=None, repr=False)
    _rca_solver: Any = field(default=None, repr=False)
    _locked_solver: str = ""

    def handle_a2a_message(self, parts: list[dict]) -> dict:
        texts = [p.get("text", "") for p in parts if "text" in p]
        full_text = "\n".join(texts).strip()

        if not full_text:
            return {"response_parts": [{"text": "No input received."}]}

        self.history.append({"role": "user", "content": full_text[:3000]})
        # Prevent OOM: keep recent history
        if len(self.history) > 24:
            self.history = self.history[-16:]

        # Route: locked solver or detect
        if self._locked_solver:
            solver_type = self._locked_solver
        else:
            solver_type = self._detect_benchmark(full_text)
            if solver_type != "generic":
                self._locked_solver = solver_type

        log.info("Solver: %s (locked=%s)", solver_type, bool(self._locked_solver))

        try:
            if solver_type == "ethernaut":
                response = self._handle_ethernaut(full_text)
            elif solver_type == "mitre":
                response = self._handle_mitre(full_text)
            elif solver_type == "rca":
                response = self._handle_rca(full_text)
            else:
                response = self._handle_generic(full_text)
        except Exception as e:
            log.error("Solver '%s' crashed: %s", solver_type, e, exc_info=True)
            response = f"Error in {solver_type}: {type(e).__name__}: {e}"

        self.history.append({"role": "assistant", "content": response[:5000]})
        return {"response_parts": [{"text": response}]}

    def _detect_benchmark(self, text: str) -> str:
        """Detect benchmark type from message content."""
        lower = text.lower()

        scores = {"ethernaut": 0, "mitre": 0, "rca": 0}

        # Ethernaut: tool names are strong signals
        ethernaut_strong = ["get_new_instance", "exec_console", "view_source",
                            "deploy_attack_contract", "submit_instance", "ethernaut"]
        ethernaut_weak = ["solidity", "smart contract", "pragma solidity",
                          "msg.sender", "delegatecall", "selfdestruct",
                          "reentrancy", "evm", "wei", "gwei"]
        scores["ethernaut"] += sum(3 for s in ethernaut_strong if s in lower)
        scores["ethernaut"] += sum(1 for s in ethernaut_weak if s in lower)

        # MITRE / Security Evaluator
        mitre_strong = ["mitre", "att&ck", "atlas", "aml.t", "prompt injection",
                        "security evaluation", "threat detection"]
        mitre_weak = ["jailbreak", "classify", "threat", "attack pattern",
                      "malicious", "phishing", "detect"]
        scores["mitre"] += sum(3 for s in mitre_strong if s in lower)
        scores["mitre"] += sum(1 for s in mitre_weak if s in lower)

        # RCA
        rca_strong = ["root cause", "arvo:", "task id:", "loc.json", "addresssanitizer",
                      "memorysanitizer", "/workspace/", "error report:",
                      "crash report", "fuzzer", "sanitizer"]
        rca_weak = ["heap-buffer-overflow", "use-after-free", "stack-overflow",
                    "crash", "backtrace", "segfault", "asan"]
        scores["rca"] += sum(3 for s in rca_strong if s in lower)
        scores["rca"] += sum(1 for s in rca_weak if s in lower)

        best = max(scores, key=scores.get)
        if scores[best] >= 3:
            return best

        # Secondary: bare attack payload → mitre
        if self._looks_like_attack(lower):
            return "mitre"

        return "generic"

    def _looks_like_attack(self, lower: str) -> bool:
        signals = ["ignore", "disregard", "forget", "override",
                   "you are now", "pretend", "act as", "from now on",
                   "system prompt", "no restrictions", "jailbreak",
                   "do anything now", "dan", "debug mode"]
        return sum(1 for s in signals if s in lower) >= 2

    def _handle_ethernaut(self, text: str) -> str:
        if self._solidity_solver is None:
            from src.solidity_solver import SoliditySolver
            self._solidity_solver = SoliditySolver()
        return self._solidity_solver.solve(text, self.history)

    def _handle_mitre(self, text: str) -> str:
        if self._mitre_detector is None:
            from src.mitre_detector import MitreDetector
            self._mitre_detector = MitreDetector()
        return self._mitre_detector.detect(text, self.history)

    def _handle_rca(self, text: str) -> str:
        if self._rca_solver is None:
            from src.rca_solver import RcaSolver
            self._rca_solver = RcaSolver()
        return self._rca_solver.solve(text, self.history)

    def _handle_generic(self, text: str) -> str:
        response = call_llm(
            text,
            system="You are an expert cybersecurity agent. Analyze the request and respond. "
                   "If tools are available, use <json>{...}</json> format.",
            model=MODEL_HAIKU,
            max_tokens=4096,
        )
        return response or "Unable to process. Please provide more context."

    def get_session_stats(self) -> dict:
        return {
            "session_id": self.session_id,
            "turns": len(self.history) // 2,
            "locked_solver": self._locked_solver or "none",
            "solvers_initialized": {
                "ethernaut": self._solidity_solver is not None,
                "mitre": self._mitre_detector is not None,
                "rca": self._rca_solver is not None,
            },
        }
