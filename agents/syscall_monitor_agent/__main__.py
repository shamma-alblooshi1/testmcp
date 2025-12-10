# =============================================================================
# agents/syscall_monitor_agent/__main__.py
# =============================================================================
# 🎯 Purpose:
# Starts the SyscallMonitorAgent as an Agent-to-Agent (A2A) server.
# - Defines the agent's metadata (AgentCard)
# - Wraps the SyscallMonitorAgent logic in a SyscallMonitorTaskManager
# - Listens for incoming syscall analysis tasks on a configurable host and port
# =============================================================================

import logging                        # Standard Python module for logging
import click                          # Library for building command-line interfaces

from server.server import A2AServer    # Our generic A2A server implementation
from models.agent import (
    AgentCard,                        # Pydantic model for describing an agent
    AgentCapabilities,                # Describes streaming & other features
    AgentSkill                       # Describes a specific skill the agent offers
)
from agents.syscall_monitor_agent.task_manager import SyscallMonitorTaskManager
                                      # TaskManager that adapts SyscallMonitorAgent to A2A
from agents.syscall_monitor_agent.agent import SyscallMonitorAgent
                                      # Our custom syscall monitoring agent logic

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
    help="Host to bind SyscallMonitorAgent server to"  # Help text for `--help`
)
@click.option(
    "--port",
    default=10003,
    help="Port for SyscallMonitorAgent server"
)
def main(host: str, port: int):
    """
    Launches the SyscallMonitorAgent A2A server.

    Args:
        host (str): Hostname or IP to bind to (default: localhost)
        port (int): TCP port to listen on (default: 10003)
    """
    # Print a friendly banner so the user knows the server is starting
    print(f"\n🚀 Starting SyscallMonitorAgent on http://{host}:{port}/\n")

    # -------------------------------------------------------------------------
    # 1) Define the agent's capabilities
    # -------------------------------------------------------------------------
    # Here we specify that this agent does NOT support streaming responses.
    # It will always send a single, complete reply.
    capabilities = AgentCapabilities(streaming=False)

    # -------------------------------------------------------------------------
    # 2) Define the agent's skill metadata
    # -------------------------------------------------------------------------
    # Single skill that covers all syscall monitoring through MCP
    skill = AgentSkill(
        id="syscall_monitor",
        name="System Call Monitoring & Analysis",
        description="Comprehensive system call monitoring, process analysis, and security assessment using MCP tools",
        tags=["syscall", "monitoring", "security", "process", "analysis", "mcp"],
        examples=[
            "Monitor system processes and their behavior",
            "Start system call monitoring for security analysis", 
            "Analyze process tree and relationships",
            "Check system compliance against security benchmarks",
            "Investigate suspicious process activity",
            "Generate comprehensive system health reports"
        ]
    )

    # -------------------------------------------------------------------------
    # 3) Compose the AgentCard for discovery
    # -------------------------------------------------------------------------
    # AgentCard is the JSON metadata that other clients/agents fetch
    # from "/.well-known/agent.json". It describes the syscall monitoring capabilities
    agent_card = AgentCard(
        name="SyscallMonitorAgent",
        description="System call monitoring and analysis agent that orchestrates MCP system tools for comprehensive security assessment",
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
    # SyscallMonitorAgent contains the orchestration logic (LLM + MCP tools).
    syscall_agent = SyscallMonitorAgent()
    # SyscallMonitorTaskManager adapts that logic to the A2A JSON-RPC protocol.
    task_manager = SyscallMonitorTaskManager(agent=syscall_agent)

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