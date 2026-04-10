"""A2A server for Cybersecurity Agent (Ethernaut Arena purple agent).

Usage:
    cd agent-cyber && python -m src.server
    ANTHROPIC_API_KEY=sk-... python -m src.server --port 9020
"""

from __future__ import annotations

import asyncio
import argparse
import logging
import os
import signal
import sys
import threading
import time
from uuid import uuid4

import uvicorn
from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.apps.jsonrpc.starlette_app import A2AStarletteApplication
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
    Message,
    Part,
    Role,
    TextPart,
)

from src.agent import CyberAgent

log = logging.getLogger("cyber.server")
VERSION = "0.5.0"

REQUEST_TIMEOUT = int(os.environ.get("A2A_REQUEST_TIMEOUT", "300"))
_agents: dict[str, tuple[CyberAgent, float]] = {}
_agents_lock = threading.Lock()


def _get_agent(context_id: str) -> CyberAgent:
    now = time.monotonic()
    with _agents_lock:
        if len(_agents) > 100:
            expired = [k for k, (_, ts) in _agents.items() if now - ts > 3600]
            for k in expired:
                del _agents[k]
        if context_id not in _agents:
            _agents[context_id] = (CyberAgent(session_id=context_id), now)
        else:
            agent, _ = _agents[context_id]
            _agents[context_id] = (agent, now)
        return _agents[context_id][0]


class CyberAgentExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        full_text = context.get_user_input() or ""
        context_id = context.context_id or "default"

        try:
            agent = _get_agent(context_id)
            result = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, agent.handle_a2a_message, [{"text": full_text}]
                ),
                timeout=REQUEST_TIMEOUT,
            )
        except asyncio.TimeoutError:
            result = {"response_parts": [{"text": f"Timeout after {REQUEST_TIMEOUT}s."}]}
        except Exception as e:
            log.error("Failed: %s", e, exc_info=True)
            result = {"response_parts": [{"text": f"Error: {e}"}]}

        response_text = result.get("response_parts", [{}])[0].get("text", "")

        await event_queue.enqueue_event(
            Message(
                kind="message",
                role=Role.agent,
                parts=[Part(root=TextPart(kind="text", text=response_text))],
                message_id=uuid4().hex,
                context_id=context_id,
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass


def build_agent_card(base_url: str = "http://localhost:9020") -> AgentCard:
    return AgentCard(
        name="Cybersecurity Agent",
        description="AI-powered smart contract security auditor for Ethernaut Arena.",
        url=f"{base_url}/",
        version=VERSION,
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[
            AgentSkill(
                id="solidity-audit",
                name="Smart Contract Security Audit",
                description="Analyze and exploit Solidity smart contract vulnerabilities.",
                tags=["security", "solidity", "ethereum", "exploit"],
                examples=[],
            ),
            AgentSkill(
                id="rca-analysis",
                name="Root Cause Analysis",
                description="Analyze fuzzer crash reports to locate root cause vulnerabilities in C/C++ codebases.",
                tags=["security", "rca", "fuzzing", "vulnerability"],
                examples=[],
            ),
            AgentSkill(
                id="threat-detection",
                name="Threat Detection",
                description="Detect prompt injection, SQL injection, XSS, and other attack patterns using multi-layer pipeline.",
                tags=["security", "mitre", "detection", "prompt-injection"],
                examples=[],
            ),
        ],
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("A2A_PORT", "9020")))
    args = parser.parse_args()

    card = build_agent_card(f"http://127.0.0.1:{args.port}")
    executor = CyberAgentExecutor()
    handler = DefaultRequestHandler(agent_executor=executor, task_store=InMemoryTaskStore())
    app = A2AStarletteApplication(agent_card=card, http_handler=handler)

    print(f"Purple Agent v{VERSION} on http://{args.host}:{args.port}")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
