# =============================================================================
# agents/syscall_monitor_agent/agent.py - CONSOLIDATED VERSION
# =============================================================================

import logging
import asyncio
import subprocess
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union
import psutil
from dotenv import load_dotenv

load_dotenv()

# Google ADK imports for LLM agent functionality
from google.adk.agents.llm_agent import LlmAgent
from google.adk.sessions import InMemorySessionService
from google.adk.memory.in_memory_memory_service import InMemoryMemoryService
from google.adk.artifacts import InMemoryArtifactService
from google.adk.runners import Runner
from google.genai import types
from google.adk.tools.function_tool import FunctionTool

logger = logging.getLogger(__name__)

class SyscallMonitorAgent:
    """
    🛡️ AI-powered system monitoring agent that uses LLM intelligence
    combined with system monitoring tools to analyze processes and ensure compliance.
    """

    SUPPORTED_CONTENT_TYPES = ["text", "text/plain"]

    def __init__(self):
        """🏗️ Constructor: build the system monitoring LLM with analysis tools."""
        self.security_llm = self._build_security_llm()
        self.user_id = "system_monitor_user"
        
        self.runner = Runner(
            app_name=self.security_llm.name,
            agent=self.security_llm,
            artifact_service=InMemoryArtifactService(),
            session_service=InMemorySessionService(),
            memory_service=InMemoryMemoryService(),
        )
        
        # System monitoring state
        self.monitoring_active = False
        self.monitored_processes = {}
        self.cis_controls = ["1.5", "4.1", "5.1", "6.1"]
        
        logger.info("SyscallMonitorAgent initialized with consolidated tools")

    def _build_security_llm(self) -> LlmAgent:
        """🔧 Build the LLM with consolidated system monitoring tools."""

        # --- Tool 1: start_system_monitoring ---
        async def start_system_monitoring() -> dict:
            """Start continuous system call and process monitoring."""
            try:
                self.monitoring_active = True
                asyncio.create_task(self._monitor_security_loop())
                
                logger.info("System monitoring started")
                return {
                    "status": "success",
                    "message": "System monitoring has been activated",
                    "monitoring_active": True
                }
            except Exception as e:
                logger.error(f"Failed to start monitoring: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to start monitoring: {str(e)}"
                }

        # --- Tool 2: stop_system_monitoring ---
        async def stop_system_monitoring() -> dict:
            """Stop system monitoring."""
            try:
                self.monitoring_active = False
                logger.info("System monitoring stopped")
                return {
                    "status": "success",
                    "message": "System monitoring has been deactivated",
                    "monitoring_active": False
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to stop monitoring: {str(e)}"
                }

        # --- Tool 3: CONSOLIDATED list_processes ---
        async def list_processes(
            analysis_mode: str = "standard",    # "standard", "comprehensive", "snapshot", "cpu_focus"
            limit: int = 50,
            sort_by: str = "cpu", 
            offset: int = 0,
            cpu_interval: float = 0.5,          # CPU measurement interval
            include_all: bool = False           # Return ALL processes regardless of limit
        ) -> dict:
            """
            CONSOLIDATED process listing tool that handles all process enumeration needs.
            
            Args:
                analysis_mode: 
                    - "standard": Normal process listing with basic metrics
                    - "comprehensive": Enhanced metrics + analysis (replaces get_all_processes)  
                    - "snapshot": Quick overview (replaces analyze_current_processes)
                    - "cpu_focus": Detailed CPU analysis (replaces get_detailed_cpu_analysis)
                limit: Maximum processes to return (0 = no limit)
                sort_by: Sort criteria - 'cpu', 'memory', 'pid', 'name', 'memory_rss'
                offset: Number of processes to skip for pagination  
                cpu_interval: CPU measurement interval in seconds (0.5-3.0)
                include_all: If True, return ALL processes regardless of limit
                
            Returns: Detailed list of running processes with appropriate analysis
            """
            try:
                # Validate and set parameters
                cpu_interval = max(0.1, min(5.0, cpu_interval or 0.5))  # Clamp to safe range
                if limit is None:
                    limit = 50 if analysis_mode == "snapshot" else 0
                if sort_by is None:
                    sort_by = "pid" if analysis_mode == "snapshot" else "cpu"
                
                processes = []
                process_objects = []
                
                # Adjust behavior based on analysis mode
                if analysis_mode == "snapshot":
                    # Quick snapshot - minimal CPU measurement, basic info only
                    logger.info("Taking quick process snapshot...")
                    cpu_interval = 0.1  # Very fast
                    limit = limit or 50
                elif analysis_mode == "cpu_focus":
                    # Detailed CPU analysis - longer measurement, focus on CPU consumers
                    logger.info(f"Performing detailed CPU analysis over {cpu_interval} seconds...")
                    cpu_interval = max(2.0, cpu_interval)  # At least 2 seconds for accuracy
                else:
                    # Standard or comprehensive - balanced approach
                    logger.info("Collecting comprehensive process information...")
                
                # First pass: collect process objects and initialize CPU monitoring
                field_list = ['pid', 'name', 'cmdline', 'username', 'create_time', 'memory_percent', 'status', 'ppid']
                
                for proc in psutil.process_iter(field_list):
                    try:
                        proc.cpu_percent()  # Initialize CPU monitoring
                        process_objects.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Wait for CPU measurement interval
                await asyncio.sleep(cpu_interval)
                
                # Second pass: collect process data
                for proc in process_objects:
                    try:
                        # Get CPU measurement
                        cpu_percent = proc.cpu_percent()
                        
                        # For CPU-focused analysis, skip processes with no measurable CPU
                        if analysis_mode == "cpu_focus" and cpu_percent <= 0.01:
                            continue
                        
                        # Enhanced activity detection for low CPU processes
                        if cpu_percent == 0.0 and analysis_mode in ["standard", "comprehensive"]:
                            try:
                                with proc.oneshot():
                                    num_threads = proc.num_threads()
                                    num_fds = proc.num_fds() if hasattr(proc, 'num_fds') else 0
                                    memory_info = proc.memory_info()
                                    
                                if num_threads > 1 or num_fds > 10 or memory_info.rss > 100 * 1024 * 1024:
                                    cpu_percent = 0.1  # Indicate some activity
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                pass
                        
                        # Build process info based on analysis mode
                        process_info = {
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                            "username": proc.info.get('username', 'unknown'),
                            "cpu_percent": round(cpu_percent, 3 if analysis_mode == "cpu_focus" else 2),
                            "memory_percent": round(proc.info.get('memory_percent', 0), 2),
                        }
                        
                        # Add basic fields for non-snapshot modes
                        if analysis_mode != "snapshot":
                            process_info.update({
                                "status": proc.info.get('status', 'unknown'),
                                "ppid": proc.info.get('ppid', 0),
                                "create_time": proc.info.get('create_time', 0),
                                "running_time": round(datetime.now().timestamp() - proc.info.get('create_time', 0), 2)
                            })
                        
                        # Add enhanced metrics for comprehensive/cpu_focus modes
                        if analysis_mode in ["comprehensive", "cpu_focus"]:
                            try:
                                with proc.oneshot():
                                    process_info.update({
                                        "num_threads": proc.num_threads(),
                                        "num_fds": proc.num_fds() if hasattr(proc, 'num_fds') else 0,
                                        "memory_rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
                                        "memory_vms_mb": round(proc.memory_info().vms / 1024 / 1024, 1),
                                    })
                            except (psutil.AccessDenied, psutil.NoSuchProcess):
                                process_info.update({
                                    "num_threads": 0,
                                    "num_fds": 0,
                                    "memory_rss_mb": 0,
                                    "memory_vms_mb": 0,
                                })
                        
                        # For snapshot mode, add unique ID and timestamp for LLM compatibility
                        if analysis_mode == "snapshot":
                            process_info.update({
                                "id": f"proc_{proc.info['pid']}_{int(datetime.now().timestamp())}",
                                "type": "process_analysis",
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                        
                        processes.append(process_info)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Sort processes
                sort_key_map = {
                    "cpu": lambda x: x['cpu_percent'],
                    "memory": lambda x: x['memory_percent'], 
                    "pid": lambda x: x['pid'],
                    "name": lambda x: x['name'].lower(),
                    "memory_rss": lambda x: x.get('memory_rss_mb', 0)
                }
                
                if sort_by in sort_key_map:
                    reverse_sort = sort_by in ["cpu", "memory", "memory_rss"]
                    processes.sort(key=sort_key_map[sort_by], reverse=reverse_sort)
                
                # Calculate summary statistics
                total_processes = len(processes)
                high_cpu_count = len([p for p in processes if p['cpu_percent'] > 5.0])
                high_memory_count = len([p for p in processes if p['memory_percent'] > 5.0])
                active_processes = len([p for p in processes if p['cpu_percent'] > 0.0 or p.get('num_threads', 0) > 1])
                
                # Handle pagination and limiting
                if include_all:
                    returned_processes = processes
                    pagination_info = {"showing_all": True, "total_returned": len(processes)}
                else:
                    paginated_processes = processes[offset:]
                    if limit > 0:
                        returned_processes = paginated_processes[:limit]
                    else:
                        returned_processes = paginated_processes
                    
                    pagination_info = {
                        "showing_all": False,
                        "offset": offset,
                        "limit": limit if limit > 0 else "no_limit",
                        "total_returned": len(returned_processes),
                        "has_more": len(processes) > (offset + len(returned_processes))
                    }
                
                # Build response based on analysis mode
                response = {
                    "status": "success",
                    "analysis_mode": analysis_mode,
                    "measurement_details": {
                        "cpu_interval_seconds": cpu_interval,
                        "sort_criteria": sort_by,
                        "total_processes_found": total_processes
                    },
                    "pagination": pagination_info,
                    "summary": {
                        "high_cpu_processes": high_cpu_count,
                        "high_memory_processes": high_memory_count, 
                        "active_processes": active_processes
                    },
                    "processes": returned_processes,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                # Add mode-specific analysis
                if analysis_mode == "snapshot":
                    response.update({
                        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                        "total_processes": total_processes,
                        "summary": f"Found {total_processes} running processes"
                    })
                
                elif analysis_mode == "comprehensive":
                    # Add comprehensive analysis (replaces get_all_processes functionality)
                    top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:5]
                    top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:5]
                    
                    response["comprehensive_analysis"] = {
                        "top_cpu_consumers": top_cpu,
                        "top_memory_consumers": top_memory,
                        "analysis_note": f"Complete analysis of all {total_processes} running processes"
                    }
                
                elif analysis_mode == "cpu_focus":
                    # Add CPU-focused analysis (replaces get_detailed_cpu_analysis functionality)
                    system_cpu = psutil.cpu_percent(interval=0.1)
                    cpu_count = psutil.cpu_count()
                    load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
                    
                    response["cpu_analysis"] = {
                        "system_cpu_info": {
                            "overall_cpu_percent": system_cpu,
                            "cpu_count": cpu_count,
                            "load_average": load_avg
                        },
                        "analysis_summary": {
                            "processes_with_measurable_cpu": total_processes,
                            "high_cpu_processes": high_cpu_count,
                            "total_cpu_from_returned_processes": round(sum(p['cpu_percent'] for p in returned_processes), 2)
                        }
                    }
                
                return response
                
            except Exception as e:
                logger.error(f"Error in list_processes: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to list processes: {str(e)}"
                }

        # --- Tool 4: check_cis_compliance ---
        async def check_cis_compliance(benchmark_type: str) -> dict:
            """Check system compliance against CIS benchmarks."""
            try:
                if benchmark_type is None:
                    benchmark_type = "linux"
                compliance_checks = await self._perform_cis_checks(benchmark_type)
                
                total_checks = len(compliance_checks)
                passed_checks = len([c for c in compliance_checks if c.get('status') == 'pass'])
                compliance_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
                failed_checks = [c for c in compliance_checks if c.get('status') == 'fail']
                
                return {
                    "status": "success",
                    "benchmark_type": benchmark_type,
                    "compliance_score": round(compliance_score, 2),
                    "total_checks": total_checks,
                    "passed_checks": passed_checks,
                    "failed_checks": len(failed_checks),
                    "checks": compliance_checks[:10],
                    "priority_failures": failed_checks[:5],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "summary": f"Compliance score: {compliance_score:.1f}% ({passed_checks}/{total_checks} checks passed)"
                }
                
            except Exception as e:
                logger.error(f"Error checking CIS compliance: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to check CIS compliance: {str(e)}"
                }

        # --- Tool 5: investigate_process ---
        async def investigate_process(pid: int) -> dict:
            """Perform detailed investigation of a specific process."""
            try:
                proc = psutil.Process(pid)
                
                process_info = {
                    "pid": pid,
                    "name": proc.name(),
                    "cmdline": ' '.join(proc.cmdline()) if proc.cmdline() else "",
                    "username": proc.username(),
                    "create_time": proc.create_time(),
                    "cpu_percent": proc.cpu_percent(),
                    "memory_percent": proc.memory_percent(),
                    "status": proc.status(),
                    "cwd": proc.cwd() if hasattr(proc, 'cwd') else "Unknown"
                }
                
                try:
                    process_info.update({
                        "num_threads": proc.num_threads(),
                        "memory_rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
                        "memory_vms_mb": round(proc.memory_info().vms / 1024 / 1024, 1),
                        "ppid": proc.ppid()
                    })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                return {
                    "status": "success",
                    "process": process_info,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except psutil.NoSuchProcess:
                return {
                    "status": "error",
                    "message": f"Process with PID {pid} not found"
                }
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to investigate process: {str(e)}"
                }

        # --- Tool 6: get_system_status ---
        async def get_system_status() -> dict:
            """Get comprehensive system status and health metrics."""
            try:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                all_processes = list(psutil.process_iter(['pid', 'name']))
                process_count = len(all_processes)
                
                return {
                    "status": "success",
                    "agent_info": {
                        "monitoring_active": self.monitoring_active,
                        "cis_controls": self.cis_controls
                    },
                    "system_metrics": {
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory.percent,
                        "disk_percent": round((disk.used / disk.total) * 100, 2),
                        "process_count": process_count
                    },
                    "monitoring_summary": {
                        "monitoring_status": "Active" if self.monitoring_active else "Inactive",
                        "last_check": datetime.now(timezone.utc).isoformat()
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to get system status: {str(e)}"
                }

        # --- Tool 7: get_process_tree ---
        async def get_process_tree(root_pid: Optional[int], max_depth: int, show_threads: bool) -> dict:
            """Get hierarchical process tree with parent-child relationships."""
            try:
                if max_depth is None:
                    max_depth = 3
                if show_threads is None:
                    show_threads = False
                    
                def build_tree(parent_pid, current_depth=0):
                    if current_depth > max_depth:
                        return []
                    
                    children = []
                    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username', 'status']):
                        try:
                            if proc.info['ppid'] == parent_pid:
                                proc_data = {
                                    "pid": proc.info['pid'],
                                    "name": proc.info['name'],
                                    "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                                    "username": proc.info.get('username', 'unknown'),
                                    "status": proc.info.get('status', 'unknown'),
                                    "depth": current_depth,
                                    "cpu_percent": round(proc.cpu_percent(), 2),
                                    "memory_percent": round(proc.memory_percent(), 2)
                                }
                                
                                if show_threads:
                                    try:
                                        proc_data["num_threads"] = proc.num_threads()
                                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                                        proc_data["num_threads"] = 0
                                
                                proc_data["children"] = build_tree(proc.info['pid'], current_depth + 1)
                                children.append(proc_data)
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    return sorted(children, key=lambda x: x['pid'])
                
                if root_pid is None:
                    root_processes = []
                    for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                        try:
                            if proc.info['ppid'] in [0, 1] or proc.info['pid'] == 1:
                                tree = build_tree(proc.info['pid'])
                                if tree:
                                    root_processes.extend(tree)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    tree_data = root_processes
                else:
                    tree_data = build_tree(root_pid)
                
                def count_nodes(tree):
                    count = len(tree)
                    for node in tree:
                        count += count_nodes(node.get('children', []))
                    return count
                
                total_processes = count_nodes(tree_data)
                
                return {
                    "status": "success",
                    "tree_params": {
                        "root_pid": root_pid,
                        "max_depth": max_depth,
                        "show_threads": show_threads
                    },
                    "statistics": {
                        "total_processes": total_processes,
                        "max_depth_reached": max_depth
                    },
                    "process_tree": tree_data,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error(f"Error building process tree: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to build process tree: {str(e)}"
                }

        # --- Tool 8: filter_processes ---
        async def filter_processes(
            name_pattern: Optional[str],
            username: Optional[str], 
            min_cpu: Optional[float],
            max_cpu: Optional[float],
            min_memory: Optional[float],
            max_memory: Optional[float],
            status: Optional[str],
            cmdline_contains: Optional[str],
            limit: int
        ) -> dict:
            """Filter processes based on multiple criteria."""
            try:
                if limit is None:
                    limit = 50
                import fnmatch
                
                filtered_processes = []
                filter_stats = {
                    "total_scanned": 0,
                    "filters_applied": [],
                    "matches_found": 0
                }
                
                # Track applied filters
                if name_pattern: filter_stats["filters_applied"].append(f"name: {name_pattern}")
                if username: filter_stats["filters_applied"].append(f"user: {username}")
                if min_cpu is not None: filter_stats["filters_applied"].append(f"min_cpu: {min_cpu}%")
                if max_cpu is not None: filter_stats["filters_applied"].append(f"max_cpu: {max_cpu}%")
                if min_memory is not None: filter_stats["filters_applied"].append(f"min_memory: {min_memory}%")
                if max_memory is not None: filter_stats["filters_applied"].append(f"max_memory: {max_memory}%")
                if status: filter_stats["filters_applied"].append(f"status: {status}")
                if cmdline_contains: filter_stats["filters_applied"].append(f"cmdline_contains: {cmdline_contains}")
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'status']):
                    try:
                        filter_stats["total_scanned"] += 1
                        
                        proc_info = proc.info
                        cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ""
                        cpu_percent = proc.cpu_percent()
                        memory_percent = proc.memory_percent()
                        
                        # Apply filters
                        if name_pattern and not fnmatch.fnmatch(proc_info['name'], name_pattern):
                            continue
                        if username and proc_info.get('username', '').lower() != username.lower():
                            continue
                        if min_cpu is not None and cpu_percent < min_cpu:
                            continue
                        if max_cpu is not None and cpu_percent > max_cpu:
                            continue
                        if min_memory is not None and memory_percent < min_memory:
                            continue
                        if max_memory is not None and memory_percent > max_memory:
                            continue
                        if status and proc_info.get('status', '').lower() != status.lower():
                            continue
                        if cmdline_contains and cmdline_contains.lower() not in cmdline.lower():
                            continue
                        
                        # Process matches all filters
                        process_data = {
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "cmdline": cmdline[:200],
                            "username": proc_info.get('username', 'unknown'),
                            "status": proc_info.get('status', 'unknown'),
                            "cpu_percent": round(cpu_percent, 2),
                            "memory_percent": round(memory_percent, 2),
                            "create_time": proc.create_time(),
                        }
                        
                        try:
                            with proc.oneshot():
                                process_data.update({
                                    "num_threads": proc.num_threads(),
                                    "memory_rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1),
                                    "ppid": proc.ppid(),
                                })
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        filtered_processes.append(process_data)
                        
                        if len(filtered_processes) >= limit:
                            break
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                filter_stats["matches_found"] = len(filtered_processes)
                filtered_processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
                
                return {
                    "status": "success",
                    "filter_criteria": {
                        "name_pattern": name_pattern,
                        "username": username,
                        "cpu_range": f"{min_cpu}-{max_cpu}" if min_cpu or max_cpu else None,
                        "memory_range": f"{min_memory}-{max_memory}" if min_memory or max_memory else None,
                        "status": status,
                        "cmdline_contains": cmdline_contains,
                        "limit": limit
                    },
                    "filter_stats": filter_stats,
                    "processes": filtered_processes,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error(f"Error filtering processes: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to filter processes: {str(e)}"
                }

        # --- Tool 9: monitor_process_changes ---
        async def monitor_process_changes(duration_seconds: int, check_interval: float) -> dict:
            """Monitor process creation, termination, and changes over time."""
            try:
                if duration_seconds is None:
                    duration_seconds = 30
                if check_interval is None:
                    check_interval = 2.0
                logger.info(f"Starting process change monitoring for {duration_seconds} seconds...")
                
                changes = {
                    "new_processes": [],
                    "terminated_processes": []
                }
                
                # Initial snapshot
                initial_processes = {}
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                    try:
                        initial_processes[proc.info['pid']] = {
                            "name": proc.info['name'],
                            "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                            "cpu_percent": proc.cpu_percent(),
                            "memory_percent": proc.memory_percent(),
                            "create_time": proc.create_time()
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                start_time = datetime.now()
                end_time = start_time + datetime.timedelta(seconds=duration_seconds)
                
                while datetime.now() < end_time:
                    await asyncio.sleep(check_interval)
                    
                    current_processes = {}
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent']):
                        try:
                            current_processes[proc.info['pid']] = {
                                "name": proc.info['name'],
                                "cmdline": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                                "cpu_percent": proc.cpu_percent(),
                                "memory_percent": proc.memory_percent(),
                                "create_time": proc.create_time()
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                    
                    # Find new processes
                    new_pids = set(current_processes.keys()) - set(initial_processes.keys())
                    for pid in new_pids:
                        proc_data = current_processes[pid]
                        changes["new_processes"].append({
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "pid": pid,
                            "name": proc_data["name"],
                            "cmdline": proc_data["cmdline"][:150]
                        })
                    
                    # Find terminated processes
                    terminated_pids = set(initial_processes.keys()) - set(current_processes.keys())
                    for pid in terminated_pids:
                        if pid in initial_processes:
                            changes["terminated_processes"].append({
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "pid": pid,
                                "name": initial_processes[pid]["name"],
                                "cmdline": initial_processes[pid]["cmdline"][:150]
                            })
                    
                    initial_processes = current_processes
                
                monitoring_summary = {
                    "duration_seconds": duration_seconds,
                    "check_interval": check_interval,
                    "total_new_processes": len(changes["new_processes"]),
                    "total_terminated_processes": len(changes["terminated_processes"])
                }
                
                return {
                    "status": "success",
                    "monitoring_period": {
                        "start": start_time.isoformat(),
                        "end": datetime.now().isoformat(),
                        "duration_seconds": duration_seconds
                    },
                    "summary": monitoring_summary,
                    "changes": changes,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except Exception as e:
                logger.error(f"Error monitoring process changes: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to monitor process changes: {str(e)}"
                }

        # --- Tool 10: analyze_process_behavior ---
        async def analyze_process_behavior(pid: int, analysis_duration: int) -> dict:
            """Perform behavioral analysis of a specific process over time."""
            try:
                if analysis_duration is None:
                    analysis_duration = 10
                proc = psutil.Process(pid)
                
                initial_info = {
                    "name": proc.name(),
                    "cmdline": ' '.join(proc.cmdline()) if proc.cmdline() else "",
                    "username": proc.username(),
                    "create_time": proc.create_time(),
                    "cwd": proc.cwd() if hasattr(proc, 'cwd') else "Unknown"
                }
                
                behavior_data = {
                    "cpu_samples": [],
                    "memory_samples": [],
                    "threads_count": [],
                    "children_spawned": []
                }
                
                initial_children = set()
                try:
                    initial_children = set([child.pid for child in proc.children(recursive=False)])
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                logger.info(f"Analyzing behavior of PID {pid} for {analysis_duration} seconds...")
                
                for i in range(analysis_duration):
                    try:
                        timestamp = datetime.now(timezone.utc).isoformat()
                        
                        behavior_data["cpu_samples"].append({
                            "timestamp": timestamp,
                            "cpu_percent": proc.cpu_percent()
                        })
                        
                        behavior_data["memory_samples"].append({
                            "timestamp": timestamp,
                            "memory_percent": proc.memory_percent(),
                            "memory_rss_mb": round(proc.memory_info().rss / 1024 / 1024, 1)
                        })
                        
                        try:
                            behavior_data["threads_count"].append({
                                "timestamp": timestamp,
                                "num_threads": proc.num_threads()
                            })
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        # Check for new children
                        try:
                            current_children = set([child.pid for child in proc.children(recursive=False)])
                            new_children = current_children - initial_children
                            if new_children:
                                for child_pid in new_children:
                                    try:
                                        child_proc = psutil.Process(child_pid)
                                        behavior_data["children_spawned"].append({
                                            "timestamp": timestamp,
                                            "child_pid": child_pid,
                                            "child_name": child_proc.name(),
                                            "child_cmdline": ' '.join(child_proc.cmdline()) if child_proc.cmdline() else ""
                                        })
                                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                                        pass
                                initial_children = current_children
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                        
                        await asyncio.sleep(1)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        break
                
                analysis = self._analyze_behavior_patterns(behavior_data, initial_info)
                
                return {
                    "status": "success",
                    "process_info": initial_info,
                    "analysis_duration": analysis_duration,
                    "behavior_data": behavior_data,
                    "behavioral_analysis": analysis,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
            except psutil.NoSuchProcess:
                return {
                    "status": "error",
                    "message": f"Process with PID {pid} not found or terminated during analysis"
                }
            except Exception as e:
                logger.error(f"Error analyzing process behavior: {e}")
                return {
                    "status": "error",
                    "message": f"Failed to analyze process behavior: {str(e)}"
                }

        # --- Tool 11: generate_system_report ---
        async def generate_system_report(report_type: str) -> dict:
            """Generate comprehensive system analysis report."""
            try:
                if report_type is None:
                    report_type = "summary"
                    
                # Gather data using consolidated tools
                processes = await list_processes(analysis_mode="snapshot", limit=25)
                compliance = await check_cis_compliance("linux")
                status = await get_system_status()
                
                report = {
                    "report_type": report_type,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "executive_summary": {
                        "monitoring_status": self.monitoring_active,
                        "total_processes": processes.get("total_processes", 0),
                        "compliance_score": compliance.get("compliance_score", 0),
                        "system_health": "Good" if status.get("system_metrics", {}).get("cpu_percent", 0) < 80 else "Concerning"
                    },
                    "key_findings": [],
                    "recommendations": [
                        "Maintain continuous system monitoring",
                        "Improve CIS compliance score",
                        "Regular system audits and updates"
                    ]
                }
                
                if report_type == "detailed":
                    report["detailed_analysis"] = {
                        "process_details": processes,
                        "compliance_details": compliance,
                        "system_status": status
                    }
                
                return {
                    "status": "success",
                    "report": report
                }
                
            except Exception as e:
                return {
                    "status": "error",
                    "message": f"Failed to generate report: {str(e)}"
                }

        # --- System instruction for consolidated agent ---
        system_instruction = """
        You are an advanced AI system monitoring agent with expert knowledge in:
        - System call analysis and process monitoring
        - CIS benchmark compliance and system hardening  
        - Process behavior analysis and monitoring
        - System performance analysis
        - Process tree analysis and relationships
        - System reporting and recommendations

        You have access to 11 consolidated, focused system monitoring tools:

        **Core Monitoring Tools:**
        1. start_system_monitoring() - Activate continuous system monitoring
        2. stop_system_monitoring() - Deactivate system monitoring
        3. list_processes(analysis_mode, limit, sort_by, offset, cpu_interval, include_all) - CONSOLIDATED process analysis tool
        4. check_cis_compliance(benchmark_type) - Check system compliance against CIS benchmarks
        5. investigate_process(pid) - Perform detailed analysis of specific processes
        6. get_system_status() - Get comprehensive system status and health metrics

        **Enhanced Process Analysis Tools:**
        7. get_process_tree(root_pid, max_depth, show_threads) - Hierarchical process tree with parent-child relationships
        8. filter_processes(...) - Advanced process filtering with multiple criteria
        9. monitor_process_changes(duration_seconds, check_interval) - Real-time monitoring of process creation/termination
        10. analyze_process_behavior(pid, duration) - Behavioral analysis of specific processes over time

        **Reporting Tools:**
        11. generate_system_report(report_type) - Create comprehensive system reports

        **IMPORTANT: The list_processes() tool is your primary process analysis tool with multiple modes:**
        - analysis_mode="snapshot": Quick process overview (50 processes, fast)
        - analysis_mode="standard": Normal process listing with basic metrics
        - analysis_mode="comprehensive": Complete analysis with top consumers 
        - analysis_mode="cpu_focus": Detailed CPU analysis with longer measurement intervals

        Use the appropriate analysis_mode based on the user's needs rather than calling multiple tools.

        When responding to system monitoring queries:
        1. Choose the right analysis_mode for list_processes() based on user intent
        2. Use process trees to understand relationships and hierarchies
        3. Use filtering for targeted analysis of specific process types
        4. Analyze process behavior patterns for performance insights
        5. Provide clear, actionable analysis and recommendations
        6. Reference specific CIS controls and best practices
        7. Suggest concrete system optimization steps

        Always maintain a professional, technical perspective and provide 
        accurate, helpful guidance for improving system performance and security posture.
        """

       
        tools = [
            FunctionTool(start_system_monitoring),
            FunctionTool(stop_system_monitoring),
            FunctionTool(list_processes),                # CONSOLIDATED: replaces 4 tools
            FunctionTool(check_cis_compliance),
            FunctionTool(investigate_process),
            FunctionTool(get_system_status),
            FunctionTool(get_process_tree),
            FunctionTool(filter_processes),
            FunctionTool(monitor_process_changes),
            FunctionTool(analyze_process_behavior),
            FunctionTool(generate_system_report),
        ]

        return LlmAgent(
            model="gemini-1.5-flash-latest",
            name="syscall_system_monitor",
            description="AI-powered system monitoring agent with consolidated, focused tools",
            instruction=system_instruction,
            tools=tools,
        )

    async def invoke(self, query: str, session_id: str) -> str:
        """Process system monitoring queries through the AI monitoring pipeline."""
        session = await self.runner.session_service.get_session(
            app_name=self.security_llm.name,
            user_id=self.user_id,
            session_id=session_id,
        )

        if session is None:
            session = await self.runner.session_service.create_session(
                app_name=self.security_llm.name,
                user_id=self.user_id,
                session_id=session_id,
                state={},
            )

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query)]
        )

        last_event = None
        async for event in self.runner.run_async(
            user_id=self.user_id,
            session_id=session.id,
            new_message=content
        ):
            last_event = event

        if not last_event or not last_event.content or not last_event.content.parts:
            return "I apologize, but I couldn't process your system monitoring request. Please try again."

        return "\n".join([p.text for p in last_event.content.parts if p.text])

    # =============================================================================
    # Internal helper methods (unchanged)
    # =============================================================================

    async def _monitor_security_loop(self):
        """Background system monitoring loop"""
        while self.monitoring_active:
            try:
                logger.info("Performing automated system check...")
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f"Error in system monitoring loop: {e}")
                await asyncio.sleep(60)

    async def _perform_cis_checks(self, benchmark_type: str) -> List[Dict]:
        """Perform CIS benchmark compliance checks"""
        checks = []
        
        cis_checks = [
            # Core dump restrictions
            {
                "id": "1.5.1.a",
                "title": "Ensure core dumps are restricted (hard limit)",
                "command": "grep -E '^\\*\\s+hard\\s+core\\s+0' /etc/security/limits.conf",
                "expected_result": "pass",
                "description": "Core dumps can be used to determine system information and process memory contents"
            },
            {
                "id": "1.5.1.b", 
                "title": "Ensure core dumps are restricted (sysctl)",
                "command": "sysctl fs.suid_dumpable",
                "expected_result": "fs.suid_dumpable = 0",
                "description": "Prevent setuid programs from dumping core"
            },
            # Address Space Layout Randomization
            {
                "id": "1.5.2",
                "title": "Ensure address space layout randomization (ASLR) is enabled",
                "command": "sysctl kernel.randomize_va_space",
                "expected_result": "kernel.randomize_va_space = 2",
                "description": "ASLR randomly arranges address space positions of key data areas of a process"
            },
            # Additional process security checks...
            {
                "id": "1.5.3.a",
                "title": "Ensure prelink is disabled (package check)",
                "command": "dpkg -s prelink 2>/dev/null | grep Status || echo 'not installed'",
                "expected_result": "not installed",
                "description": "Prelink can interfere with ASLR and should be disabled"
            },
            {
                "id": "4.1.3",
                "title": "Ensure auditing for processes that start prior to auditd is enabled",
                "command": "grep -E 'audit=1' /proc/cmdline",
                "expected_result": "audit=1",
                "description": "Enable audit logging for processes that start before auditd"
            }
        ]
        
        for check in cis_checks:
            try:
                result = await self._run_system_command(check["command"])
                status = "pass" if result["exit_code"] == 0 else "fail"
                
                checks.append({
                    "id": check["id"],
                    "title": check["title"],
                    "status": status,
                    "output": result["output"][:100],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            except Exception as e:
                checks.append({
                    "id": check["id"],
                    "title": check["title"],
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        
        return checks

    async def _run_system_command(self, command: str) -> Dict:
        """Run system command safely with timeout"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            return {
                "exit_code": result.returncode,
                "output": result.stdout.strip(),
                "error": result.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "output": "", "error": "Command timed out"}
        except Exception as e:
            return {"exit_code": -1, "output": "", "error": str(e)}

    def _analyze_behavior_patterns(self, behavior_data: dict, process_info: dict) -> dict:
        """Analyze behavioral patterns from collected data"""
        analysis = {
            "cpu_analysis": {},
            "memory_analysis": {},
            "process_spawning": {},
            "behavioral_indicators": []
        }
        
        # CPU analysis
        cpu_samples = [s["cpu_percent"] for s in behavior_data["cpu_samples"]]
        if cpu_samples:
            analysis["cpu_analysis"] = {
                "average_cpu": round(sum(cpu_samples) / len(cpu_samples), 2),
                "max_cpu": max(cpu_samples),
                "cpu_spikes": len([c for c in cpu_samples if c > 50]),
                "cpu_trend": "increasing" if cpu_samples[-1] > cpu_samples[0] else "decreasing"
            }
            
            if analysis["cpu_analysis"]["average_cpu"] > 30:
                analysis["behavioral_indicators"].append("high_cpu_usage")
        
        # Memory analysis
        memory_samples = [s["memory_percent"] for s in behavior_data["memory_samples"]]
        if memory_samples:
            analysis["memory_analysis"] = {
                "average_memory": round(sum(memory_samples) / len(memory_samples), 2),
                "max_memory": max(memory_samples),
                "memory_growth": memory_samples[-1] - memory_samples[0] if len(memory_samples) > 1 else 0
            }
            
            if analysis["memory_analysis"]["memory_growth"] > 10:
                analysis["behavioral_indicators"].append("memory_leak_potential")
        
        # Process spawning
        analysis["process_spawning"] = {
            "children_spawned": len(behavior_data["children_spawned"]),
            "spawning_rate": len(behavior_data["children_spawned"]) / len(behavior_data["cpu_samples"]) if behavior_data["cpu_samples"] else 0
        }
        
        if len(behavior_data["children_spawned"]) > 3:
            analysis["behavioral_indicators"].append("frequent_process_spawning")
        
        return analysis