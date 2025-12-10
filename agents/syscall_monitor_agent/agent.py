# =============================================================================
# agents/syscall_monitor_agent/agent.py
# =============================================================================
# 🎯 Purpose:
#   A simple syscall monitoring orchestrator agent that:
#     1) Discovers available MCP system monitoring tools
#     2) Calls MCP tools based on user requests
#     3) Provides intelligent analysis of system call monitoring results
# =============================================================================

import logging                              # Built-in module to log info, warnings, errors
from dotenv import load_dotenv              # For loading environment variables from a .env file

load_dotenv()  # Read .env in project root so that GOOGLE_API_KEY is available

# Gemini LLM agent and supporting services from Google's ADK:
from google.adk.agents.llm_agent import LlmAgent
from google.adk.sessions import InMemorySessionService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.artifacts import InMemoryArtifactService
from google.adk.runners import Runner

# Gemini types for wrapping messages
from google.genai import types

# Helper to wrap our Python functions as "tools" for the LLM to call
from google.adk.tools.function_tool import FunctionTool
from typing import Optional
# TODO: Import your MCP connection utilities here
# from utilities.mcp.wiremcp_connector import WireMCPConnector

# Create a module-level logger using this file's name
logger = logging.getLogger(__name__)


class SyscallMonitorAgent:
    """
    🖥️ Simple Syscall Monitoring Agent that:
      - Provides two MCP tools: list_mcp_tools() and call_mcp_tool(...)
      - On syscall monitoring requests:
          1) Calls list_mcp_tools() to see what system tools are available
          2) Calls call_mcp_tool(tool_name, parameters) to execute system analysis
          3) Provides intelligent analysis and recommendations based on results
    """

    # Declare which content types this agent accepts by default
    SUPPORTED_CONTENT_TYPES = ["text", "text/plain"]

    def __init__(self):
        """
        🏗️ Constructor: build the internal orchestrator LLM with MCP tools.
        """
        # Build the LLM with MCP tools and system instruction
        self.orchestrator = self._build_orchestrator()

        # A fixed user_id to group all syscall monitoring calls into one session
        self.user_id = "syscall_monitor_user"

        # Runner wires together: agent logic, sessions, memory, artifacts
        self.runner = Runner(
            app_name=self.orchestrator.name,
            agent=self.orchestrator,
            artifact_service=InMemoryArtifactService(),
            session_service=InMemorySessionService(),
            memory_service=InMemoryMemoryService(),
        )

        # TODO: Initialize your MCP connector here
        # self.mcp_connector = WireMCPConnector()

    def _build_orchestrator(self) -> LlmAgent:
        """
        🔧 Internal: define the LLM, its system instruction, and MCP communication tools.
        """

        # --- Tool 1: list_mcp_tools ---
        async def list_mcp_tools() -> list[dict]:
            """
            Fetch all available system monitoring tools from the MCP server.
            
            Returns:
                list[dict]: List of available MCP tools with their descriptions
            """
            try:
                # TODO: Replace with your MCP connector call to list tools
                # tools = await self.mcp_connector.list_tools()
                # return tools
                
                # Placeholder implementation
                return [
                    {"name": "start_system_monitoring", "description": "Start continuous system call and process monitoring"},
                    {"name": "stop_system_monitoring", "description": "Stop system monitoring"},
                    {"name": "list_processes", "description": "Get detailed process listing with multiple analysis modes"},
                    {"name": "check_cis_compliance", "description": "Check system compliance against CIS benchmarks"},
                    {"name": "investigate_process", "description": "Perform detailed investigation of a specific process"},
                    {"name": "get_system_status", "description": "Get comprehensive system status and health metrics"},
                    {"name": "get_process_tree", "description": "Get hierarchical process tree with relationships"},
                    {"name": "filter_processes", "description": "Filter processes based on multiple criteria"},
                    {"name": "monitor_process_changes", "description": "Monitor process creation and termination over time"},
                    {"name": "analyze_process_behavior", "description": "Perform behavioral analysis of specific processes"},
                    {"name": "generate_system_report", "description": "Generate comprehensive system analysis report"}
                ]
            except Exception as e:
                logger.error(f"Error listing MCP tools: {e}")
                return []

        # --- Tool 2: call_mcp_tool ---
        async def call_mcp_tool(tool_name: str, parameters: Optional[dict] = None) -> str:
            """
            Call a specific system monitoring tool on the MCP server.
            
            Args:
                tool_name (str): Name of the MCP tool to call
                parameters (dict): Parameters to pass to the tool
                
            Returns:
                str: Result from the MCP tool execution
            """
            try:
                if parameters is None:
                    parameters = {}
                
                # TODO: Replace with your MCP connector call
                # result = await self.mcp_connector.call_tool(tool_name, parameters)
                # return result
                
                # Placeholder implementation
                return f"🔧 Called MCP tool '{tool_name}' with parameters: {parameters}\n✅ Tool execution completed successfully."
                
            except Exception as e:
                logger.error(f"Error calling MCP tool {tool_name}: {e}")
                return f"❌ Error calling MCP tool '{tool_name}': {str(e)}"

        # --- System instruction for the LLM ---
        system_instr = (
            "You are a System Call Monitoring Agent that orchestrates system analysis tools through MCP (Model Context Protocol).\n\n"
            
            "You have two tools available:\n"
            "1) list_mcp_tools() → returns available system monitoring tools from the MCP server\n"
            "2) call_mcp_tool(tool_name: str, parameters: dict) → executes a specific system tool\n\n"
            
            "When handling system monitoring requests:\n"
            "1. First call list_mcp_tools() to see what tools are available\n"
            "2. Choose the most appropriate tool(s) for the user's request\n"
            "3. Call call_mcp_tool() with the correct tool name and parameters\n"
            "4. Analyze the results and provide clear, actionable insights\n"
            "5. Suggest follow-up actions or additional analysis when relevant\n\n"
            
            "Common system monitoring scenarios:\n"
            "• Process analysis: Use 'list_processes', 'get_process_tree', or 'filter_processes' tools\n"
            "• Security monitoring: Use 'start_system_monitoring', 'check_cis_compliance', or 'investigate_process' tools\n"
            "• System health: Use 'get_system_status' or 'generate_system_report' tools\n"
            "• Behavioral analysis: Use 'monitor_process_changes' or 'analyze_process_behavior' tools\n"
            "• Incident investigation: Use 'investigate_process' with specific PIDs\n\n"
            
            "Always provide professional system analysis with:\n"
            "- Clear explanations of findings and potential security implications\n"
            "- Performance metrics and resource usage analysis\n"
            "- Security recommendations and compliance status\n"
            "- Proper formatting with emojis for readability\n"
            "- Actionable next steps for system administrators\n"
            "- Risk assessment when suspicious activity is detected\n\n"
            
            "Focus on:\n"
            "• Process behavior anomalies\n"
            "• Resource consumption patterns\n"
            "• Security compliance violations\n"
            "• System performance bottlenecks\n"
            "• Potential malware or intrusion indicators"
        )

        # Wrap our Python functions into ADK FunctionTool objects
        tools = [
            FunctionTool(list_mcp_tools),
            FunctionTool(call_mcp_tool),
        ]

        # Create and return the LlmAgent with everything wired up
        return LlmAgent(
            model="gemini-1.5-flash-latest",
            name="syscall_monitor_orchestrator",
            description="System call monitoring orchestrator that uses MCP tools for comprehensive system analysis.",
            instruction=system_instr,
            tools=tools,
        )

    async def invoke(self, query: str, session_id: str) -> str:
        """
        🔄 Public: send a user query through the syscall monitoring LLM pipeline,
        ensuring session reuse or creation, and return the final analysis.
        
        Args:
            query (str): User's system monitoring request
            session_id (str): Session identifier for conversation continuity
            
        Returns:
            str: System monitoring analysis and recommendations
        """
        # 1) Try to fetch an existing session
        session = await self.runner.session_service.get_session(
            app_name=self.orchestrator.name,
            user_id=self.user_id,
            session_id=session_id,
        )

        # 2) If not found, create a new session with empty state
        if session is None:
            session = await self.runner.session_service.create_session(
                app_name=self.orchestrator.name,
                user_id=self.user_id,
                session_id=session_id,
                state={},
            )

        # 3) Wrap the user's text in a Gemini Content object
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query)]
        )

        # 🚀 Run the agent using the Runner and collect the last event
        last_event = None
        async for event in self.runner.run_async(
            user_id=self.user_id,
            session_id=session.id,
            new_message=content
        ):
            last_event = event

        # 🧹 Fallback: return empty string if something went wrong
        if not last_event or not last_event.content or not last_event.content.parts:
            return ""

        # 📤 Extract and join all text responses into one string
        return "\n".join([p.text for p in last_event.content.parts if p.text])