"""
Unit Tests for Autonomous AI Cloud Red-Team & Chaos Adversary Engine
"""

import pytest
from core.attack_graph import AttackGraph, AttackNode, AttackEdge
from core.blast_radius import BlastRadiusCalculator
from core.mitre_mapper import MitreMapper
from core.self_healer import SelfHealingEngine
from core.agent import AutonomousRedTeamAgent


def test_mitre_mapper():
    tech = MitreMapper.map_finding("imdsv1_enabled")
    assert tech is not None
    assert tech.technique_id == "T1552.005"
    assert tech.severity == "CRITICAL"

    tech_s3 = MitreMapper.map_finding("s3_public_read")
    assert tech_s3.technique_id == "T1530"


def test_attack_graph_pathfinding():
    graph = AttackGraph()
    n1 = AttackNode(node_id="A", resource_type="NETWORK", name="Entry", arn="arn:1")
    n2 = AttackNode(node_id="B", resource_type="EC2", name="Server", arn="arn:2")
    n3 = AttackNode(node_id="C", resource_type="ADMIN", name="Root", arn="arn:3", is_critical_asset=True)

    graph.add_asset(n1)
    graph.add_asset(n2)
    graph.add_asset(n3)

    graph.add_exploit_path(AttackEdge(source_id="A", target_id="B", action="SSRF", mitre_technique_id="T1552.005"))
    graph.add_exploit_path(AttackEdge(source_id="B", target_id="C", action="ELEVATE", mitre_technique_id="T1098.001"))

    paths = graph.find_all_attack_paths("A", "C")
    assert len(paths) == 1
    assert paths[0] == ["A", "B", "C"]

    shortest = graph.get_shortest_attack_vector("A", "C")
    assert shortest == ["A", "B", "C"]


def test_blast_radius_calculator():
    graph = AttackGraph()
    n1 = AttackNode(node_id="Entry", resource_type="NETWORK", name="Entry", arn="arn:1")
    n2 = AttackNode(node_id="Crown", resource_type="ADMIN", name="Crown", arn="arn:2", is_critical_asset=True)
    graph.add_asset(n1)
    graph.add_asset(n2)
    graph.add_exploit_path(AttackEdge(source_id="Entry", target_id="Crown", action="DIRECT", mitre_technique_id="T1078"))

    score = BlastRadiusCalculator.calculate_score(graph, "Entry", "Crown")
    assert score["target_exposed"] is True
    assert score["shortest_hops"] == 1
    assert score["blast_radius_index"] > 60.0


def test_self_healing_engine():
    patch_imds = SelfHealingEngine.generate_remediation_patch("imdsv1_enabled", "web_server")
    assert "http_tokens                 = \"required\"" in patch_imds["terraform"]

    patch_s3 = SelfHealingEngine.generate_remediation_patch("s3_public_read", "my-data-bucket")
    assert "block_public_acls       = true" in patch_s3["terraform"]


def test_autonomous_red_team_agent_end_to_end():
    agent = AutonomousRedTeamAgent("Test-Env")
    sample_findings = [
        {
            "finding_type": "imdsv1_enabled",
            "source_id": "Internet_Perimeter",
            "source_type": "NETWORK",
            "target_id": "Role_Worker",
            "target_type": "IAM_ROLE",
            "exploit_action": "SSRF_IMDS",
            "cost": 1.0
        },
        {
            "finding_type": "iam_wildcard_admin",
            "source_id": "Role_Worker",
            "source_type": "IAM_ROLE",
            "target_id": "Crown_Jewel_Admin",
            "target_type": "ADMIN",
            "exploit_action": "PRIV_ESC",
            "is_critical": True,
            "cost": 1.0
        }
    ]
    agent.ingest_telemetry_findings(sample_findings)
    result = agent.run_autonomous_simulation()

    assert result["total_steps"] == 2
    assert result["attack_paths_count"] >= 1
    assert result["blast_radius"]["target_exposed"] is True
    assert len(result["remediation_patches"]) >= 1
    assert "flowchart LR" in result["mermaid_diagram"]
