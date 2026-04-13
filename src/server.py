"""A2A server for Cybersecurity Agent (CyberGYM purple agent).

Usage:
    cd agent-cyber && python -m src.server
    ANTHROPIC_API_KEY=sk-... python -m src.server --port 9020
"""

from __future__ import annotations

import argparse
import logging
import os

import uvicorn
from a2a.server.apps.jsonrpc.starlette_app import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentSkill,
)

from src.executor import CyberExecutor

log = logging.getLogger("cyber.server")
VERSION = "0.8.0"


class NoHistoryTaskStore(InMemoryTaskStore):
    """Task store that clears history to reduce memory for large challenge files."""

    async def save(self, task, context=None):
        task.history = []
        return await super().save(task, context)


def build_agent_card(base_url: str = "http://localhost:9020") -> AgentCard:
    return AgentCard(
        name="CyberGym Purple",
        description="AI-powered vulnerability PoC generator for CyberGYM benchmarks.",
        url=f"{base_url}/",
        version=VERSION,
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[
            AgentSkill(
                id="poc",
                name="PoC Generation",
                description="Analyze vulnerable source code and generate exploit PoC that reproduces the vulnerability.",
                tags=["cybersecurity", "exploit", "poc", "vulnerability"],
                examples=[],
            ),
        ],
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.environ.get("A2A_PORT", "9020")))
    parser.add_argument("--card-url", default=None)
    args = parser.parse_args()

    card = build_agent_card(args.card_url or f"http://127.0.0.1:{args.port}")
    executor = CyberExecutor()
    handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=NoHistoryTaskStore(),
    )
    app = A2AStarletteApplication(
        agent_card=card,
        http_handler=handler,
        max_content_length=None,  # Large challenge file tarballs
    )

    print(f"CyberGym Purple v{VERSION} on http://{args.host}:{args.port}")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
