"""A2A Executor — state machine, one step per request.

Each execute() call:
  1. Gets/creates agent for context
  2. Creates fresh TaskUpdater with THIS request's event_queue
  3. Calls agent.step() which does ONE state transition
  4. If agent.done → complete task and cleanup
"""

from __future__ import annotations

import logging

from a2a.server.agent_execution import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.tasks import TaskUpdater
from a2a.types import TaskState

from src.agent import CyberAgent

log = logging.getLogger("cyber.executor")

_agents: dict[str, CyberAgent] = {}


class CyberExecutor(AgentExecutor):
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        ctx_id = context.context_id or "default"
        msg = context.message

        if not msg:
            return

        task = context.current_task
        if task and task.status and task.status.state in (
            TaskState.completed, TaskState.canceled, TaskState.failed, TaskState.rejected,
        ):
            return

        # Get or create agent
        if ctx_id not in _agents:
            _agents[ctx_id] = CyberAgent()
        agent = _agents[ctx_id]

        # Fresh updater with THIS request's event queue
        task_id = task.id if task else ctx_id
        updater = TaskUpdater(event_queue, task_id, ctx_id)

        try:
            # Only start_work on first call; follow-ups already have a working task
            if agent.state.value == "init":
                await updater.start_work()
            await agent.step(msg, updater)

            if agent.done:
                await updater.complete()
                _agents.pop(ctx_id, None)
        except Exception as e:
            log.error("[%s] Agent failed: %s", ctx_id, e, exc_info=True)
            try:
                await updater.failed(str(e))
            except Exception:
                pass
            _agents.pop(ctx_id, None)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass
