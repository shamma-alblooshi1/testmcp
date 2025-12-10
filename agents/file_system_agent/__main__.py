# =============================================================================
# agents/filesystem_monitor_agent/__main__.py
# =============================================================================
# 🎯 Purpose:
# Starts the FilesystemMonitorAgent as an Agent-to-Agent (A2A) server.
# - Defines the agent's metadata (AgentCard)
# - Wraps the FilesystemMonitorAgent logic in a FilesystemMonitorTaskManager
# - Listens for incoming filesystem analysis tasks on a configurable host and port
# =============================================================================

import logging                        # Standard Python module for logging
import click                          # Library for building command-line interfaces

from server.server import A2AServer    # Our generic A2A server implementation
from models.agent import (
    AgentCard,                        # Pydantic model for describing an agent
    AgentCapabilities,                # Describes streaming & other features
    AgentSkill                       # Describes a specific skill the agent offers
)
from agents.file_system_agent.task_manager import FilesystemMonitorTaskManager
                                      # TaskManager that adapts FilesystemMonitorAgent to A2A
from agents.file_system_agent.agent import FilesystemMonitorAgent
                                      # Our custom filesystem monitoring agent logic

# -----------------------------------------------------------------------------
# ⚙️ Logging setup
# -----------------------------------------------------------------------------
# Configure the root logger to print INFO-level messages to the console.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# ✨ CLI Entrypoint
# -----------------------------------------------------------------------------
@click.command()                     # Decorator: makes `main` a CLI command
@click.option(
    "--host",                        # CLI flag name
    default="localhost",             # Default value if flag not provided
    help="Host to bind FilesystemMonitorAgent server to"  # Help text for `--help`
)
@click.option(
    "--port",
    default=10001,
    help="Port for FilesystemMonitorAgent server"
)
def main(host: str, port: int):
    """
    Launches the FilesystemMonitorAgent A2A server.

    Args:
        host (str): Hostname or IP to bind to (default: localhost)
        port (int): TCP port to listen on (default: 10001)
    """
    # Print a friendly banner so the user knows the server is starting
    print(f"\n🚀 Starting FilesystemMonitorAgent on http://{host}:{port}/\n")

    # -------------------------------------------------------------------------
    # 1) Define the agent's capabilities
    # -------------------------------------------------------------------------
    # Here we specify that this agent does NOT support streaming responses.
    # It will always send a single, complete reply.
    capabilities = AgentCapabilities(streaming=False)

    # -------------------------------------------------------------------------
    # 2) Define the agent's skill metadata
    # -------------------------------------------------------------------------
    # Single skill that covers all filesystem monitoring through MCP
    skill = AgentSkill(
        id="filesystem_monitor",
        name="File System Monitoring & Analysis",
        description="Comprehensive file system monitoring, access tracking, and security assessment using MCP tools",
        tags=["filesystem", "monitoring", "security", "files", "analysis", "mcp"],
        examples=[
            "Monitor directory for file changes and access patterns",
            "Start file system monitoring for security analysis", 
            "Track file permission changes and modifications",
            "Analyze file access patterns over time",
            "Monitor sensitive directories for unauthorized access",
            "Generate file system activity reports"
        ]
    )

    # -------------------------------------------------------------------------
    # 3) Compose the AgentCard for discovery
    # -------------------------------------------------------------------------
    # AgentCard is the JSON metadata that other clients/agents fetch
    # from "/.well-known/agent.json". It describes the filesystem monitoring capabilities
    agent_card = AgentCard(
        name="FilesystemMonitorAgent",
        description="File system monitoring and analysis agent that orchestrates MCP filesystem tools for comprehensive security assessment",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        defaultInputModes=["text"],
        defaultOutputModes=["text"],
        capabilities=capabilities,
        skills=[skill]
    )

    # -------------------------------------------------------------------------
    # 4) Instantiate the core logic and its TaskManager
    # -------------------------------------------------------------------------
    # FilesystemMonitorAgent contains the orchestration logic (LLM + MCP tools).
    filesystem_agent = FilesystemMonitorAgent()
    # FilesystemMonitorTaskManager adapts that logic to the A2A JSON-RPC protocol.
    task_manager = FilesystemMonitorTaskManager(agent=filesystem_agent)

    # -------------------------------------------------------------------------
    # 5) Create and start the A2A server
    # -------------------------------------------------------------------------
    # A2AServer wires up:
    # - HTTP routes (POST "/" for tasks, GET "/.well-known/agent.json" for discovery)
    # - our AgentCard metadata
    # - the TaskManager that handles incoming requests
    server = A2AServer(
        host=host,
        port=port,
        agent_card=agent_card,
        task_manager=task_manager
    )
    server.start()  # Blocks here, serving requests until the process is killed


# -----------------------------------------------------------------------------
# Entrypoint guard
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()