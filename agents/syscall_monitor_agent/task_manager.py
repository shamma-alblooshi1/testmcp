# =============================================================================
# agents/syscall_monitor_agent/task_manager.py
# =============================================================================
# 🎯 Purpose:
# Connects the SyscallMonitorAgent class to the Agent-to-Agent (A2A) protocol by
# handling incoming JSON-RPC "tasks/send" requests for syscall monitoring. It:
# 1. Receives a SendTaskRequest model with syscall monitoring queries
# 2. Stores the user message in memory
# 3. Calls SyscallMonitorAgent.invoke() to orchestrate MCP system tools
# 4. Updates the task status and appends the analysis to task history
# 5. Returns a SendTaskResponse containing the completed syscall monitoring Task
# =============================================================================

# -----------------------------------------------------------------------------
# 📦 Imports
# -----------------------------------------------------------------------------
import logging                            # Python's built-in logging module

# InMemoryTaskManager provides an in-memory store and locking for tasks
from server.task_manager import InMemoryTaskManager

# Data models for handling A2A JSON-RPC requests/responses and task structures
from models.request import SendTaskRequest, SendTaskResponse
from models.task import Message, TaskStatus, TaskState, TextPart

# The core business logic: SyscallMonitorAgent with async MCP orchestration
from agents.syscall_monitor_agent.agent import SyscallMonitorAgent

# -----------------------------------------------------------------------------
# 🪵 Logger setup
# -----------------------------------------------------------------------------
# Create a logger specific to this module using its __name__
logger = logging.getLogger(__name__)


class SyscallMonitorTaskManager(InMemoryTaskManager):
    """
    🧩 TaskManager for SyscallMonitorAgent:

    - Inherits storage, upsert_task, and locking from InMemoryTaskManager
    - Overrides on_send_task() to:
      * save the incoming syscall monitoring request
      * call the SyscallMonitorAgent.invoke() to orchestrate MCP tools
      * update the task status and history with analysis results
      * wrap and return the result as SendTaskResponse

    Simple orchestration that lets the agent handle MCP tool selection and execution.
    """
    
    def __init__(self, agent: SyscallMonitorAgent):
        """
        Initialize the TaskManager with a SyscallMonitorAgent instance.

        Args:
            agent (SyscallMonitorAgent): The core syscall monitoring orchestrator
                                        that knows how to use MCP tools for
                                        system analysis.
        """
        # Call the parent constructor to set up self.tasks and self.lock
        super().__init__()
        # Store a reference to our SyscallMonitorAgent for later use
        self.agent = agent

    def _get_user_text(self, request: SendTaskRequest) -> str:
        """
        Extract the raw user text from the incoming SendTaskRequest.

        Args:
            request (SendTaskRequest): The incoming JSON-RPC request
                                       containing a TaskSendParams object
                                       with syscall monitoring query.

        Returns:
            str: The text content the user sent (first TextPart).
        """
        # The request.params.message.parts is a list of TextPart objects.
        # We take the first element's .text attribute containing the syscall query.
        return request.params.message.parts[0].text

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        """
        Handle a new syscall monitoring task:

        1. Store the incoming user message in memory (or update existing task)
        2. Extract the user's syscall monitoring query for processing
        3. Call SyscallMonitorAgent.invoke() to orchestrate MCP system tools
        4. Wrap the analysis results in a Message/TextPart
        5. Update the Task status to COMPLETED and append the analysis
        6. Return a SendTaskResponse containing the updated Task with results

        Args:
            request (SendTaskRequest): The JSON-RPC request with TaskSendParams
                                      containing syscall monitoring query

        Returns:
            SendTaskResponse: A JSON-RPC response with the completed syscall
                             monitoring Task including MCP tool results
        """
        # Log receipt of a new syscall monitoring task along with its ID
        logger.info(f"SyscallMonitorTaskManager received task {request.params.id}")

        # Step 1: Save or update the task in memory.
        # upsert_task() will create a new Task if it doesn't exist,
        # or append the incoming user message to existing history.
        task = await self.upsert_task(request.params)

        # Step 2: Extract the actual syscall monitoring query the user sent
        user_text = self._get_user_text(request)

        # Step 3: Call the SyscallMonitorAgent to orchestrate MCP tools
        # Since SyscallMonitorAgent.invoke() is an async function,
        # await it to get the returned analysis string.
        try:
            syscall_analysis = await self.agent.invoke(
                user_text,
                request.params.sessionId
            )
            
            # Ensure we have some response
            if not syscall_analysis or not syscall_analysis.strip():
                syscall_analysis = "❌ System analysis completed, but no specific results were generated. Please try a more specific request."
                
        except Exception as e:
            # Handle any errors during syscall analysis
            logger.error(f"Error during syscall analysis for task {request.params.id}: {str(e)}")
            syscall_analysis = f"❌ System analysis failed: {str(e)}\n\nPlease check your request and try again."

        # Step 4: Wrap the syscall analysis string in a TextPart, then in a Message
        reply_message = Message(
            role="agent",               # Mark this as an "agent" response
            parts=[TextPart(text=syscall_analysis)]  # The agent's syscall analysis
        )

        # Step 5: Update the task status to COMPLETED and append our analysis
        # Use the lock to avoid race conditions with other coroutines.
        async with self.lock:
            # Mark the task as done
            task.status = TaskStatus(state=TaskState.COMPLETED)
            # Add the agent's syscall analysis to the task's history
            task.history.append(reply_message)

        # Log successful completion
        logger.info(f"SyscallMonitorAgent completed task {request.params.id}")

        # Step 6: Return a SendTaskResponse, containing the JSON-RPC id
        # (mirroring the request.id) and the updated Task model with analysis.
        return SendTaskResponse(id=request.id, result=task)