# =============================================================================
# agents/syscall_monitor_agent/task_manager.py
# =============================================================================

import logging
from server.task_manager import InMemoryTaskManager
from models.request import SendTaskRequest, SendTaskResponse
from models.task import Message, TaskStatus, TaskState, TextPart
from agents.syscall_monitor_agent.agent import SyscallMonitorAgent

logger = logging.getLogger(__name__)

class SyscallMonitorTaskManager(InMemoryTaskManager):
    """
    🛡️ TaskManager for SyscallMonitorAgent:
    
    - Inherits storage, upsert_task, and locking from InMemoryTaskManager
    - Overrides on_send_task() to:
      * save the incoming security query
      * call the SyscallMonitorAgent.invoke() for AI security analysis
      * update the task status and history
      * return the security analysis response
    """
    
    def __init__(self, agent: SyscallMonitorAgent):
        """
        Initialize the TaskManager with a SyscallMonitorAgent instance.
        
        Args:
            agent (SyscallMonitorAgent): The AI security monitoring agent
        """
        super().__init__()
        self.agent = agent

    def _get_user_text(self, request: SendTaskRequest) -> str:
        """
        Extract the user's security query from the request.
        
        Args:
            request (SendTaskRequest): The incoming A2A request
            
        Returns:
            str: The user's security query text
        """
        return request.params.message.parts[0].text

    async def on_send_task(self, request: SendTaskRequest) -> SendTaskResponse:
        """
        Handle a security monitoring task:
        
        1. Store the incoming user query in memory
        2. Extract the security query text
        3. Call SyscallMonitorAgent.invoke() for AI-powered security analysis
        4. Wrap the analysis response in a Message
        5. Update the Task status to COMPLETED and append the reply
        6. Return a SendTaskResponse with the security analysis
        
        Args:
            request (SendTaskRequest): The A2A request with security query
            
        Returns:
            SendTaskResponse: The A2A response with security analysis
        """
        logger.info(f"SyscallMonitorTaskManager received security task {request.params.id}")

        # Step 1: Save or update the task in memory
        task = await self.upsert_task(request.params)

        # Step 2: Extract the user's security query
        user_query = self._get_user_text(request)

        # Step 3: Call the AI security agent for analysis
        security_analysis = await self.agent.invoke(
            user_query,
            request.params.sessionId
        )

        # Step 4: Wrap the security analysis in a Message
        analysis_message = Message(
            role="agent",
            parts=[TextPart(text=security_analysis)]
        )

        # Step 5: Update task status and append the security analysis
        async with self.lock:
            task.status = TaskStatus(state=TaskState.COMPLETED)
            task.history.append(analysis_message)

        # Step 6: Return the completed security analysis task
        return SendTaskResponse(id=request.id, result=task)