"""A2A Executor — single-shot, one execute() per challenge.

Each execute() call:
  1. Creates a new CyberAgent
  2. Calls agent.step() which generates PoC and submits artifact
  3. Completes the task
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

        task_id = task.id if task else ctx_id
        updater = TaskUpdater(event_queue, task_id, ctx_id)

        try:
            agent = CyberAgent()
            await updater.start_work()
            await agent.step(msg, updater)

            if agent.done:
                try:
                    await updater.complete()
                except RuntimeError:
                    pass
        except Exception as e:
            log.error("[%s] Agent failed: %s", ctx_id, e, exc_info=True)
            try:
                await updater.failed(str(e))
            except Exception:
                pass

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass
