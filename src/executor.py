"""A2A Executor — bridges A2A protocol to CyberAgent with TaskUpdater support.

Multi-turn flow:
  Call 1 (challenge): executor creates task → agent.run blocks on test loop
  Call 2+ (test results): executor delivers message to agent's queue, no task ops
  Call 1 returns: agent submitted artifact → executor completes task
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

        # Skip terminal tasks
        task = context.current_task
        if task and task.status and task.status.state in (
            TaskState.completed, TaskState.canceled, TaskState.failed, TaskState.rejected,
        ):
            return

        agent = _agents.get(ctx_id)

        # Follow-up call: agent exists and is waiting for test results
        # Just deliver the message — NO task management ops
        if agent and agent._challenge_received:
            log.info("[%s] Delivering test result to waiting agent", ctx_id)
            await agent.run(msg, None)
            return

        # First call: create agent, task, and run full flow
        agent = CyberAgent()
        _agents[ctx_id] = agent

        updater = TaskUpdater(event_queue, task.id if task else ctx_id, ctx_id)

        if not task:
            await updater.new_task(msg)

        await updater.start_work()

        try:
            await agent.run(msg, updater)
            # agent.run blocks until PoC is submitted (done=True)
            # or rejected (also done=True)
            await updater.complete()
        except Exception as e:
            log.error("[%s] Agent failed: %s", ctx_id, e, exc_info=True)
            try:
                await updater.failed(str(e))
            except Exception:
                pass
        finally:
            _agents.pop(ctx_id, None)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        pass
