# =============================================================================
# agents/filesystem_monitor_agent/agent.py
# =============================================================================
# 🎯 Purpose:
#   A simple filesystem monitoring orchestrator agent that:
#     1) Discovers available MCP filesystem monitoring tools
#     2) Calls MCP tools based on user requests
#     3) Provides intelligent analysis of filesystem monitoring results
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


class FilesystemMonitorAgent:
    """
    📁 Simple Filesystem Monitoring Agent that:
      - Provides two MCP tools: list_mcp_tools() and call_mcp_tool(...)
      - On filesystem monitoring requests:
          1) Calls list_mcp_tools() to see what filesystem tools are available
          2) Calls call_mcp_tool(tool_name, parameters) to execute filesystem analysis
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

        # A fixed user_id to group all filesystem monitoring calls into one session
        self.user_id = "filesystem_monitor_user"

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
            Fetch all available filesystem monitoring tools from the MCP server.
            
            Returns:
                list[dict]: List of available MCP tools with their descriptions
            """
            try:
                # TODO: Replace with your MCP connector call to list tools
                # tools = await self.mcp_connector.list_tools()
                # return tools
                
                # Placeholder implementation - matches the filesystem MCP tools
                return [
                    {"name": "start_fs_monitoring", "description": "Start monitoring file system events on specified paths"},
                    {"name": "stop_fs_monitoring", "description": "Stop all file system monitoring"},
                    {"name": "get_monitoring_status", "description": "Get current file system monitoring status"},
                    {"name": "get_fs_events", "description": "Retrieve collected file system events with filtering"},
                    {"name": "monitor_directory", "description": "Monitor a directory for a specific duration"},
                    {"name": "set_event_filters", "description": "Configure which file system events to capture"},
                    {"name": "export_monitoring_logs", "description": "Export file system events to file"},
                    {"name": "analyze_file_access", "description": "Analyze file access patterns over time"},
                    {"name": "get_file_permissions", "description": "Get detailed file permission information"},
                    {"name": "monitor_permission_changes", "description": "Monitor permission changes on files"},
                    {"name": "clear_event_history", "description": "Clear collected file system events"}
                ]
            except Exception as e:
                logger.error(f"Error listing MCP tools: {e}")
                return []

        # --- Tool 2: call_mcp_tool ---
        async def call_mcp_tool(tool_name: str, parameters: Optional[dict] = None) -> str:
            """
            Call a specific filesystem monitoring tool on the MCP server.
            
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
            "You are a File System Monitoring Agent that orchestrates filesystem analysis tools through MCP (Model Context Protocol).\n\n"
            
            "You have two tools available:\n"
            "1) list_mcp_tools() → returns available filesystem monitoring tools from the MCP server\n"
            "2) call_mcp_tool(tool_name: str, parameters: dict) → executes a specific filesystem tool\n\n"
            
            "When handling filesystem monitoring requests:\n"
            "1. First call list_mcp_tools() to see what tools are available\n"
            "2. Choose the most appropriate tool(s) for the user's request\n"
            "3. Call call_mcp_tool() with the correct tool name and parameters\n"
            "4. Analyze the results and provide clear, actionable insights\n"
            "5. Suggest follow-up actions or additional analysis when relevant\n\n"
            
            "Common filesystem monitoring scenarios:\n"
            "• Directory monitoring: Use 'start_fs_monitoring' or 'monitor_directory' tools\n"
            "• File access analysis: Use 'analyze_file_access' or 'get_fs_events' tools\n"
            "• Permission monitoring: Use 'monitor_permission_changes' or 'get_file_permissions' tools\n"
            "• Security auditing: Use 'set_event_filters' to focus on security events\n"
            "• Compliance checking: Monitor sensitive directories like /etc, /var/log, user homes\n"
            "• Incident investigation: Use 'get_fs_events' with filtering for forensic analysis\n"
            "• Performance analysis: Use 'export_monitoring_logs' for detailed analysis\n\n"
            
            "SECURITY FOCUS AREAS:\n"
            "• Unauthorized file access attempts\n"
            "• Permission escalation indicators (chmod operations)\n"
            "• Suspicious file creation/deletion patterns\n"
            "• Access to sensitive files (/etc/passwd, /etc/shadow, SSH keys)\n"
            "• Unusual file modification times (off-hours activity)\n"
            "• Mass file operations (potential ransomware indicators)\n"
            "• Configuration file tampering\n\n"
            
            "Always provide professional filesystem analysis with:\n"
            "- Clear explanations of file access patterns and security implications\n"
            "- Risk assessment for detected activities\n"
            "- Compliance status regarding file permissions and access controls\n"
            "- Performance impact analysis of filesystem operations\n"
            "- Proper formatting with emojis for readability\n"
            "- Actionable recommendations for security hardening\n"
            "- Timeline analysis for incident investigation\n"
            "- Correlation with known attack patterns when relevant\n\n"
            
            "ANALYSIS PRIORITIES:\n"
            "1. Security threats and unauthorized access\n"
            "2. Compliance violations and permission issues\n"
            "3. Performance bottlenecks and I/O patterns\n"
            "4. Data integrity and backup verification\n"
            "5. User behavior analysis and access patterns\n\n"
            
            "When suspicious activity is detected, immediately recommend:\n"
            "• Enhanced monitoring of affected areas\n"
            "• Permission audits and access control reviews\n"
            "• Log correlation with other security tools\n"
            "• Incident response procedures if warranted"
        )

        # Wrap our Python functions into ADK FunctionTool objects
        tools = [
            FunctionTool(list_mcp_tools),
            FunctionTool(call_mcp_tool),
        ]

        # Create and return the LlmAgent with everything wired up
        return LlmAgent(
            model="gemini-1.5-flash-latest",
            name="filesystem_monitor_orchestrator",
            description="Filesystem monitoring orchestrator that uses MCP tools for comprehensive file system analysis.",
            instruction=system_instr,
            tools=tools,
        )

    async def invoke(self, query: str, session_id: str) -> str:
        """
        🔄 Public: send a user query through the filesystem monitoring LLM pipeline,
        ensuring session reuse or creation, and return the final analysis.
        
        Args:
            query (str): User's filesystem monitoring request
            session_id (str): Session identifier for conversation continuity
            
        Returns:
            str: Filesystem monitoring analysis and recommendations
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