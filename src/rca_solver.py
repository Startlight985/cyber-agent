"""RCA-Bench Solver — Root Cause Analysis of security vulnerabilities.

Protocol (verified from green agent source):
  1. Green sends crash report with task description
  2. Purple sends "execute: <bash command>" to explore codebase
  3. Green returns XML: <returncode>0</returncode><output>...</output>
  4. Purple writes loc.json to /workspace/shared/loc.json
  5. Purple sends "[TASK FINISHED]"

loc.json format (array, not object):
[
  {"function": "func_name", "file": "path/to/file.c", "line_start": 42, "line_end": 50},
  ...
]

Scoring: file_acc, func_recall, line_iou (IoU >= 0.5), line_proximity
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum
from typing import Any

from src.llm import call_llm, MODEL_SONNET

log = logging.getLogger("cyber.rca")


class RcaPhase(Enum):
    INIT = "init"           # Received crash report, haven't explored yet
    EXPLORING = "exploring"  # Sending execute: commands to explore codebase
    SUBMITTING = "submitting"  # Writing loc.json
    DONE = "done"


# ── Crash Pattern Recognition ────────────────────────────────

CRASH_PATTERNS = {
    "heap-buffer-overflow": "CWE-122",
    "heap-use-after-free": "CWE-416",
    "stack-buffer-overflow": "CWE-121",
    "stack-overflow": "CWE-674",
    "use-after-free": "CWE-416",
    "double-free": "CWE-415",
    "null-dereference": "CWE-476",
    "integer-overflow": "CWE-190",
    "out-of-bounds": "CWE-125",
    "division-by-zero": "CWE-369",
    "memory-leak": "CWE-401",
    "uninitialized-value": "CWE-457",
    "buffer-overflow": "CWE-120",
    "segfault": "CWE-476",
    "assertion-failure": "CWE-617",
    "data-race": "CWE-362",
    "use-after-poison": "CWE-416",
    "container-overflow": "CWE-787",
    "global-buffer-overflow": "CWE-120",
    "signed-integer-overflow": "CWE-190",
    "negative-size-param": "CWE-131",
    "shift-exponent": "CWE-682",
    "timeout": "CWE-835",
    "oom": "CWE-789",
}


def detect_crash_type(text: str) -> tuple[str, str]:
    """Detect crash type → (type, CWE)."""
    lower = text.lower()
    for pattern, cwe in CRASH_PATTERNS.items():
        if pattern in lower:
            return pattern, cwe
    return "unknown", "CWE-Unknown"


def extract_stack_frames(text: str) -> list[dict]:
    """Extract stack frames from sanitizer/GDB output."""
    frames = []
    # ASAN format: #0 0x... in func_name /path/file.c:42:10
    for m in re.finditer(r"#(\d+)\s+\S+\s+in\s+(\S+)\s+(\S+?):(\d+)", text):
        frames.append({
            "frame": int(m.group(1)),
            "function": m.group(2),
            "file": m.group(3),
            "line": int(m.group(4)),
        })
    if frames:
        return frames

    # GDB format
    for m in re.finditer(r"#(\d+)\s+(?:\S+\s+in\s+)?(\S+)\s*\([^)]*\)\s+at\s+(\S+):(\d+)", text):
        frames.append({
            "frame": int(m.group(1)),
            "function": m.group(2),
            "file": m.group(3),
            "line": int(m.group(4)),
        })
    if frames:
        return frames

    # Python traceback
    for m in re.finditer(r'File "([^"]+)", line (\d+), in (\S+)', text):
        frames.append({"file": m.group(1), "line": int(m.group(2)), "function": m.group(3)})

    return frames


# ── System Prompt ────────────────────────────────────────────

RCA_SYSTEM = """You are an expert security vulnerability analyst performing root cause analysis.

## Your Environment
You are connected to an ARVO Docker container with the vulnerable codebase at /workspace/src-vul/.
You can execute bash commands by outputting: execute: <command>

## Your Task
Given a fuzzer crash report, trace the ROOT CAUSE (where the bug was INTRODUCED, not where it crashes).

## Strategy
1. First: explore the codebase structure (find relevant files)
2. Then: read the code around crash locations from the stack trace
3. Trace backwards: the crash point is NOT always the root cause
4. Identify WHERE the fix should go (usually a missing check, wrong size, etc.)
5. Submit 3 candidate locations ranked by confidence

## Command Format
Output ONE command per response:
execute: <bash command>

## Submission
When ready, write loc.json:
execute: cat > /workspace/shared/loc.json << 'LOCEOF'
[
  {"function": "func1", "file": "relative/path.c", "line_start": 42, "line_end": 50},
  {"function": "func2", "file": "relative/path2.c", "line_start": 100, "line_end": 110}
]
LOCEOF

Then output: [TASK FINISHED]

## Critical Rules
- File paths in loc.json should be RELATIVE (e.g., "magick/utility.c" not "/workspace/src-vul/magick/utility.c")
- Line numbers are 1-indexed, inclusive
- Submit 3 candidate locations (top-3 predictions)
- Root cause ≠ crash location. Trace BACKWARDS through the call chain.
- ONE command per response. Wait for output before next command.
"""


class RcaSolver:
    """RCA-Bench solver — multi-turn codebase analysis via execute: commands."""

    def __init__(self):
        self.phase = RcaPhase.INIT
        self.crash_report: str = ""
        self.crash_type: str = ""
        self.cwe: str = ""
        self.frames: list[dict] = []
        self.explored_files: list[str] = []
        self.findings: list[str] = []
        self.turn_count: int = 0
        self.max_explore_turns: int = 15

    def solve(self, message: str, history: list[dict] | None = None) -> str:
        """Process green agent message and return next action."""
        self.turn_count += 1

        # Phase: INIT — first message is the crash report / task description
        if self.phase == RcaPhase.INIT:
            self.crash_report = message
            self.crash_type, self.cwe = detect_crash_type(message)
            self.frames = extract_stack_frames(message)
            self.phase = RcaPhase.EXPLORING

            # First command: explore the codebase
            if self.frames:
                # Start by reading the crash file
                f = self.frames[0]
                filepath = f["file"]
                line = f["line"]
                start = max(1, line - 20)
                end = line + 20
                return f"execute: sed -n '{start},{end}p' {filepath}"
            else:
                return "execute: find /workspace/src-vul -type f -name '*.c' -o -name '*.cpp' -o -name '*.h' | head -30"

        # Phase: EXPLORING — got command output, decide next action
        if self.phase == RcaPhase.EXPLORING:
            # Parse command output
            output = self._parse_command_output(message)
            self.findings.append(output[:2000])

            # If we've explored enough or running out of turns, submit
            if self.turn_count >= self.max_explore_turns:
                self.phase = RcaPhase.SUBMITTING
                return self._generate_submission(history)

            # Use LLM to decide next command
            return self._decide_next_command(message, history)

        # Phase: SUBMITTING — confirm submission
        if self.phase == RcaPhase.SUBMITTING:
            if "returncode" in message and "0" in message:
                self.phase = RcaPhase.DONE
                return "[TASK FINISHED]"
            # Submission might have failed, retry
            return self._generate_submission(history)

        # Phase: DONE
        return "[TASK FINISHED]"

    def _parse_command_output(self, message: str) -> str:
        """Extract output from green agent's XML response."""
        m = re.search(r"<output>(.*?)</output>", message, re.DOTALL)
        if m:
            return m.group(1).strip()
        return message[:3000]

    def _decide_next_command(self, message: str, history: list[dict] | None) -> str:
        """Use LLM to decide the next bash command to execute."""
        prompt = self._build_explore_prompt(message, history)

        response = call_llm(prompt, system=RCA_SYSTEM, model=MODEL_SONNET, max_tokens=1024, temperature=0)

        if not response:
            return self._fallback_explore_command()

        # Extract execute: command from response
        m = re.search(r"execute:\s*(.+)", response, re.MULTILINE)
        if m:
            cmd = m.group(1).strip()
            # If LLM decided to write loc.json, switch to SUBMITTING
            if "loc.json" in cmd or "/workspace/shared/" in cmd:
                self.phase = RcaPhase.SUBMITTING
            return f"execute: {cmd}"

        # If LLM output loc.json submission directly
        if "loc.json" in response or "LOCEOF" in response:
            self.phase = RcaPhase.SUBMITTING
            # Extract the full execute command
            m2 = re.search(r"(execute:.*?)(?:\n\n|$)", response, re.DOTALL)
            if m2:
                return m2.group(1)

        # Fallback
        return self._fallback_explore_command()

    def _build_explore_prompt(self, message: str, history: list[dict] | None) -> str:
        parts = []

        parts.append(f"## Crash Report Summary")
        parts.append(f"Type: {self.crash_type} ({self.cwe})")
        if self.frames:
            parts.append("Stack frames:")
            for f in self.frames[:5]:
                parts.append(f"  #{f.get('frame', '?')} {f.get('function', '?')} at {f['file']}:{f['line']}")

        parts.append(f"\n## Turn {self.turn_count}/{self.max_explore_turns}")

        if self.turn_count >= self.max_explore_turns - 2:
            parts.append("⚠ RUNNING OUT OF TURNS. Submit loc.json NOW.")

        parts.append(f"\n## Latest Command Output")
        parts.append(message[:3000])

        if history:
            parts.append(f"\n## Recent History ({len(history)} turns)")
            for turn in history[-6:]:
                content = turn.get("content", "")[:800]
                parts.append(f"[{turn.get('role', '')}]: {content}")

        parts.append("\n## What's your next command? Output exactly one: execute: <command>")
        parts.append("If you have enough info, write loc.json and finish.")

        return "\n".join(parts)

    def _generate_submission(self, history: list[dict] | None) -> str:
        """Generate loc.json submission based on findings."""
        prompt = self._build_submission_prompt(history)

        response = call_llm(prompt, system=RCA_SYSTEM, model=MODEL_SONNET, max_tokens=2048, temperature=0)

        if response:
            # Try to extract the execute: cat > loc.json command
            m = re.search(r"(execute:.*?LOCEOF)", response, re.DOTALL)
            if m:
                self.phase = RcaPhase.SUBMITTING
                return m.group(1)

            # Try to extract JSON array
            m2 = re.search(r"\[[\s\S]*?\]", response)
            if m2:
                try:
                    locations = json.loads(m2.group(0))
                    return self._write_loc_json(locations)
                except json.JSONDecodeError:
                    pass

        # Fallback: use stack frames
        return self._fallback_submission()

    def _build_submission_prompt(self, history: list[dict] | None) -> str:
        parts = [
            f"## Task: Write loc.json submission NOW",
            f"Crash type: {self.crash_type} ({self.cwe})",
        ]

        if self.frames:
            parts.append("\nStack frames:")
            for f in self.frames[:5]:
                parts.append(f"  #{f.get('frame', '?')} {f.get('function', '?')} at {f['file']}:{f['line']}")

        parts.append("\nFindings from exploration:")
        for finding in self.findings[-5:]:
            parts.append(finding[:500])

        parts.append("\nWrite the execute: cat > /workspace/shared/loc.json command with 3 candidate locations.")
        parts.append("Remember: file paths should be RELATIVE, not absolute.")

        return "\n".join(parts)

    def _write_loc_json(self, locations: list[dict]) -> str:
        """Generate the execute: command to write loc.json."""
        json_str = json.dumps(locations, indent=2)
        return f"execute: cat > /workspace/shared/loc.json << 'LOCEOF'\n{json_str}\nLOCEOF"

    def _fallback_submission(self) -> str:
        """Generate loc.json from stack frames when LLM fails."""
        locations = []
        for f in self.frames[:3]:
            filepath = f["file"]
            # Make relative: strip /src/, /workspace/src-vul/ etc.
            for prefix in ["/workspace/src-vul/", "/workspace/src/", "/src/", "/workspace/"]:
                if filepath.startswith(prefix):
                    filepath = filepath[len(prefix):]
                    break
            locations.append({
                "function": f.get("function", ""),
                "file": filepath,
                "line_start": max(1, f["line"] - 5),
                "line_end": f["line"] + 5,
            })

        if not locations:
            locations = [{"function": "unknown", "file": "unknown.c", "line_start": 1, "line_end": 10}]

        return self._write_loc_json(locations)

    def _fallback_explore_command(self) -> str:
        """Fallback exploration commands based on turn count."""
        if self.frames and self.turn_count <= 3:
            # Explore the first few crash files
            idx = min(self.turn_count - 1, len(self.frames) - 1)
            f = self.frames[idx]
            return f"execute: sed -n '{max(1, f['line']-30)},{f['line']+30}p' {f['file']}"
        elif self.turn_count <= 5:
            return "execute: find /workspace/src-vul -type f \\( -name '*.c' -o -name '*.cpp' \\) | head -20"
        else:
            # Time to submit
            self.phase = RcaPhase.SUBMITTING
            return self._fallback_submission()
