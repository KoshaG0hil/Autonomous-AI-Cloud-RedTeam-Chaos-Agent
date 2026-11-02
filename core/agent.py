"""
Autonomous AI Cloud Red-Team ReAct Agent
Orchestrates autonomous adversary simulation, hypothesis generation, attack graph traversal,
and self-healing remediation generation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from .attack_graph import AttackGraph, AttackNode, AttackEdge
from .blast_radius import BlastRadiusCalculator
from .mitre_mapper import MitreMapper
from .self_healer import SelfHealingEngine


class AgentStep(BaseModel):
    step_number: int
    thought: str
    action: str
    target: str
    mitre_technique: str
    observation: str
    status: str  # SUCCESS, BLOCKED, EXPLOITED


class AutonomousRedTeamAgent:
    """Autonomous ReAct agent that emulates advanced adversary decision loops in cloud environments."""

    def __init__(self, target_environment: str = "Production-AWS"):
        self.target_environment = target_environment
        self.attack_graph = AttackGraph()
        self.execution_log: List[AgentStep] = []
        self.discovered_findings: List[Dict[str, Any]] = []

    def ingest_telemetry_findings(self, findings: List[Dict[str, Any]]):
        """Ingests raw cloud audit/recon findings into structured assets and exploit edges."""
        self.discovered_findings.extend(findings)

        # Standard entrypoint and crown jewel
        entrypoint = AttackNode(
            node_id="Internet_Perimeter",
            resource_type="NETWORK",
            name="Public Internet Gateway",
            arn="arn:aws:ec2:global:000000000000:gateway/igw-public",
            compromised=True
        )
        crown_jewel = AttackNode(
            node_id="Crown_Jewel_Admin",
            resource_type="ADMIN",
            name="IAM Administrator Access & Customer Secrets",
            arn="arn:aws:iam::000000000000:role/OrganizationAccountAccessRole",
            is_critical_asset=True
        )
        self.attack_graph.add_asset(entrypoint)
        self.attack_graph.add_asset(crown_jewel)

        for f in findings:
            src_node = AttackNode(
                node_id=f["source_id"],
                resource_type=f.get("source_type", "ASSET"),
                name=f.get("source_name", f["source_id"]),
                arn=f.get("source_arn", f"arn:aws:asset:{f['source_id']}")
            )
            dst_node = AttackNode(
                node_id=f["target_id"],
                resource_type=f.get("target_type", "ASSET"),
                name=f.get("target_name", f["target_id"]),
                arn=f.get("target_arn", f"arn:aws:asset:{f['target_id']}"),
                is_critical_asset=f.get("is_critical", False)
            )
            self.attack_graph.add_asset(src_node)
            self.attack_graph.add_asset(dst_node)

            technique = MitreMapper.map_finding(f.get("finding_type", ""))
            tech_id = technique.technique_id if technique else "T1580"

            edge = AttackEdge(
                source_id=f["source_id"],
                target_id=f["target_id"],
                action=f.get("exploit_action", "PIVOT"),
                mitre_technique_id=tech_id,
                cost=f.get("cost", 1.0)
            )
            self.attack_graph.add_exploit_path(edge)

    def run_autonomous_simulation(self) -> Dict[str, Any]:
        """
        Executes autonomous ReAct reasoning loop to find viable multi-hop attack vectors.
        """
        step = 1
        paths = self.attack_graph.find_all_attack_paths("Internet_Perimeter", "Crown_Jewel_Admin")

        if not paths:
            # Check paths from first compromised node
            all_nodes = list(self.attack_graph.nodes_data.keys())
            start_node = all_nodes[0] if all_nodes else "Internet_Perimeter"
            paths = self.attack_graph.find_all_attack_paths(start_node, "Crown_Jewel_Admin")
        else:
            start_node = "Internet_Perimeter"

        simulated_path = paths[0] if paths else []

        for i in range(len(simulated_path) - 1):
            u = simulated_path[i]
            v = simulated_path[i + 1]
            edge_data = self.attack_graph.graph.get_edge_data(u, v) or {}
            action = edge_data.get("action", "PIVOT")
            mitre_id = edge_data.get("mitre", "T1580")

            thought = f"Agent identifies viable transition from {u} to {v} via {action}."
            observation = f"Exploit simulated successfully. Elevated privileges acquired on {v}."

            self.execution_log.append(AgentStep(
                step_number=step,
                thought=thought,
                action=action,
                target=v,
                mitre_technique=mitre_id,
                observation=observation,
                status="EXPLOITED"
            ))
            step += 1

        blast_radius = BlastRadiusCalculator.calculate_score(
            self.attack_graph,
            start_node,
            "Crown_Jewel_Admin"
        )

        chokepoints = self.attack_graph.identify_chokepoints()

        # Generate self-healing patches
        patches = []
        for finding in self.discovered_findings:
            f_type = finding.get("finding_type")
            res_id = finding.get("source_id")
            if f_type and res_id:
                patch = SelfHealingEngine.generate_remediation_patch(f_type, res_id)
                patches.append(patch)

        return {
            "environment": self.target_environment,
            "total_steps": len(self.execution_log),
            "execution_log": [s.model_dump() for s in self.execution_log],
            "attack_paths_count": len(paths),
            "shortest_path": simulated_path,
            "blast_radius": blast_radius,
            "chokepoints": chokepoints,
            "remediation_patches": patches,
            "mermaid_diagram": self.attack_graph.export_mermaid_diagram()
        }
