# =============================================================================
# agents/syscall_monitor_agent/__main__.py
# =============================================================================

import logging
import click

from server.server import A2AServer
from models.agent import (
    AgentCard,
    AgentCapabilities,
    AgentSkill
)
from agents.syscall_monitor_agent.task_manager import SyscallMonitorTaskManager
from agents.syscall_monitor_agent.agent import SyscallMonitorAgent

# -----------------------------------------------------------------------------
# ⚙️ Logging setup
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# ✨ CLI Entrypoint
# -----------------------------------------------------------------------------
@click.command()
@click.option(
    "--host",
    default="localhost",
    help="Host to bind SyscallMonitorAgent server to"
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
        port (int): TCP port to listen on (default: 1000)
    """
    print(f"\n🛡️ Starting SyscallMonitorAgent on http://{host}:{port}/\n")

    # -------------------------------------------------------------------------
    # 1) Define the agent's capabilities
    # -------------------------------------------------------------------------
    capabilities = AgentCapabilities(streaming=False)

        # -------------------------------------------------------------------------
    # 2) Define the agent's skills metadata
    # -------------------------------------------------------------------------
    skills = [
        AgentSkill(
            id="process_monitoring",
            name="Process Monitoring",
            description="Monitor and analyze running processes and system calls",
            tags=["processes", "monitoring", "syscalls", "analysis"],
            examples=[
                "List all running processes",
                "Monitor process creation and termination",
                "Analyze CPU and memory usage by processes"
            ]
        ),
        AgentSkill(
            id="process_analysis",
            name="Process Analysis",
            description="Perform detailed analysis of process behavior and relationships",
            tags=["processes", "analysis", "behavior", "trees"],
            examples=[
                "Analyze process tree relationships",
                "Filter processes by specific criteria",
                "Investigate specific process behavior over time"
            ]
        ),
        AgentSkill(
            id="system_monitoring",
            name="System Monitoring",
            description="Monitor system performance and resource utilization",
            tags=["system", "performance", "monitoring", "resources"],
            examples=[
                "Get system status and health metrics",
                "Analyze CPU usage patterns",
                "Monitor system resource consumption"
            ]
        ),
        AgentSkill(
            id="cis_compliance",
            name="CIS Benchmark Compliance",
            description="Check and verify CIS benchmark compliance for system hardening",
            tags=["cis", "compliance", "benchmarks", "hardening"],
            examples=[
                "Check CIS benchmark compliance",
                "Verify system security configurations",
                "Audit system hardening status"
            ]
        ),
        AgentSkill(
            id="system_reporting",
            name="System Reporting",
            description="Generate comprehensive system analysis and monitoring reports",
            tags=["reports", "analysis", "documentation", "monitoring"],
            examples=[
                "Generate system monitoring report",
                "Create process analysis summary",
                "Document system performance metrics"
            ]
        )
    ]

    # -------------------------------------------------------------------------
    # 3) Compose the AgentCard for discovery
    # -------------------------------------------------------------------------
    agent_card = AgentCard(
        name="SyscallMonitorAgent",
        description="Security monitoring agent that analyzes system calls for threats and enforces CIS compliance",
        url=f"http://{host}:{port}/",
        version="1.0.0",
        defaultInputModes=["text"],
        defaultOutputModes=["text"],
        capabilities=capabilities,
        skills=skills
    )

    # -------------------------------------------------------------------------
    # 4) Instantiate the core logic and its TaskManager
    # -------------------------------------------------------------------------
    syscall_agent = SyscallMonitorAgent()
    task_manager = SyscallMonitorTaskManager(agent=syscall_agent)

    # -------------------------------------------------------------------------
    # 5) Create and start the A2A server
    # -------------------------------------------------------------------------
    server = A2AServer(
        host=host,
        port=port,
        agent_card=agent_card,
        task_manager=task_manager
    )
    server.start()


# -----------------------------------------------------------------------------
# Entrypoint guard
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()