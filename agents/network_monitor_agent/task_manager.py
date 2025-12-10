# =============================================================================
# agents/network_monitor_agent/task_manager.py
# =============================================================================
# 🎯 Purpose:
# Connects the NetworkMonitorAgent class to the Agent-to-Agent (A2A) protocol by
# handling incoming JSON-RPC "tasks/send" requests for network monitoring. It:
# 1. Receives a SendTaskRequest model with network monitoring queries
# 2. Stores the user message in memory
# 3. Calls NetworkMonitorAgent.invoke() to orchestrate MCP network tools
# 4. Updates the task status and appends the analysis to task history
# 5. Returns a SendTaskResponse containing the completed network monitoring Task
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

# The core business logic: NetworkMonitorAgent with async MCP orchestration
from agents.network_monitor_agent.agent import NetworkMonitorAgent

# -----------------------------------------------------------------------------
# 🪵 Logger setup
# -----------------------------------------------------------------------------
# Create a logger specific to this module using its __name__
logger = logging.getLogger(__name__)


class NetworkMonitorTaskManager(InMemoryTaskManager):
    """
    🧩 TaskManager for NetworkMonitorAgent:

    - Inherits storage, upsert_task, and locking from InMemoryTaskManager
    - Overrides on_send_task() to:
      * save the incoming network monitoring request
      * call the NetworkMonitorAgent.invoke() to orchestrate MCP tools
      * update the task status and history with analysis results
      * wrap and return the result as SendTaskResponse

    Simple orchestration that lets the agent handle MCP tool selection and execution.
    """
    
    def __init__(self, agent: NetworkMonitorAgent):
        """
        Initialize the TaskManager with a NetworkMonitorAgent instance.

        Args:
            agent (NetworkMonitorAgent): The core network monitoring orchestrator
                                        that knows how to use MCP tools for
                                        network analysis.
        """
        # Call the parent constructor to set up self.tasks and self.lock
        super().__init__()
        # Store a reference to our NetworkMonitorAgent for later use
        self.agent = agent

    def _get_user_text(self, request: SendTaskRequest) -> str:
        """
        Extract the raw user text from the incoming SendTaskRequest.

        Args:
            request (SendTaskRequest): The incoming JSON-RPC request
                                       containing a TaskSendParams object
                                       with network monitoring query.

        Returns:
            str: The text content the user sent (first TextPart).
        """
        # The request.params.message.parts is a list of TextPart objects.
        # We take the first element's .text attribute containing the network query.
        return request.params.message.parts[0].text

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        """
        Handle a new network monitoring task:

        1. Store the incoming user message in memory (or update existing task)
        2. Extract the user's network monitoring query for processing
        3. Call NetworkMonitorAgent.invoke() to orchestrate MCP network tools
        4. Wrap the analysis results in a Message/TextPart
        5. Update the Task status to COMPLETED and append the analysis
        6. Return a SendTaskResponse containing the updated Task with results

        Args:
            request (SendTaskRequest): The JSON-RPC request with TaskSendParams
                                      containing network monitoring query

        Returns:
            SendTaskResponse: A JSON-RPC response with the completed network
                             monitoring Task including MCP tool results
        """
        # Log receipt of a new network monitoring task along with its ID
        logger.info(f"NetworkMonitorTaskManager received task {request.params.id}")

        # Step 1: Save or update the task in memory.
        # upsert_task() will create a new Task if it doesn't exist,
        # or append the incoming user message to existing history.
        task = await self.upsert_task(request.params)

        # Step 2: Extract the actual network monitoring query the user sent
        user_text = self._get_user_text(request)

        # Step 3: Call the NetworkMonitorAgent to orchestrate MCP tools
        # Since NetworkMonitorAgent.invoke() is an async function,
        # await it to get the returned analysis string.
        try:
            network_analysis = await self.agent.invoke(
                user_text,
                request.params.sessionId
            )
            
            # Ensure we have some response
            if not network_analysis or not network_analysis.strip():
                network_analysis = "❌ Network analysis completed, but no specific results were generated. Please try a more specific request."
                
        except Exception as e:
            # Handle any errors during network analysis
            logger.error(f"Error during network analysis for task {request.params.id}: {str(e)}")
            network_analysis = f"❌ Network analysis failed: {str(e)}\n\nPlease check your request and try again."

        # Step 4: Wrap the network analysis string in a TextPart, then in a Message
        reply_message = Message(
            role="agent",               # Mark this as an "agent" response
            parts=[TextPart(text=network_analysis)]  # The agent's network analysis
        )

        # Step 5: Update the task status to COMPLETED and append our analysis
        # Use the lock to avoid race conditions with other coroutines.
        async with self.lock:
            # Mark the task as done
            task.status = TaskStatus(state=TaskState.COMPLETED)
            # Add the agent's network analysis to the task's history
            task.history.append(reply_message)

        # Log successful completion
        logger.info(f"NetworkMonitorAgent completed task {request.params.id}")

        # Step 6: Return a SendTaskResponse, containing the JSON-RPC id
        # (mirroring the request.id) and the updated Task model with analysis.
        return SendTaskResponse(id=request.id, result=task)