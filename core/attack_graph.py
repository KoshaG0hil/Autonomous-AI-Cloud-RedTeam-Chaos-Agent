"""
Attack Graph Engine
Constructs directed multi-hop attack graphs across AWS entities using NetworkX.
Calculates shortest compromise paths, chokepoints (cut vertices), and target reachability.
"""

from typing import List, Dict, Any, Tuple
import networkx as nx
from pydantic import BaseModel


class AttackNode(BaseModel):
    node_id: str
    resource_type: str  # EC2, IAM_ROLE, S3_BUCKET, LAMBDA, KMS_KEY, ADMIN
    name: str
    arn: str
    compromised: bool = False
    is_critical_asset: bool = False


class AttackEdge(BaseModel):
    source_id: str
    target_id: str
    action: str  # e.g., "IMDS_SSRF", "ASSUME_ROLE", "READ_BUCKET", "PIVOT"
    mitre_technique_id: str
    cost: float = 1.0


class AttackGraph:
    """Manages directed attack graphs for cloud environments."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes_data: Dict[str, AttackNode] = {}

    def add_asset(self, node: AttackNode):
        self.nodes_data[node.node_id] = node
        self.graph.add_node(
            node.node_id,
            resource_type=node.resource_type,
            name=node.name,
            arn=node.arn,
            is_critical=node.is_critical_asset
        )

    def add_exploit_path(self, edge: AttackEdge):
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            action=edge.action,
            mitre=edge.mitre_technique_id,
            weight=edge.cost
        )

    def find_all_attack_paths(self, start_node_id: str, target_node_id: str) -> List[List[str]]:
        """Finds all viable paths from an entry point to the target critical asset."""
        if not self.graph.has_node(start_node_id) or not self.graph.has_node(target_node_id):
            return []
        try:
            return list(nx.all_simple_paths(self.graph, source=start_node_id, target=target_node_id))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def get_shortest_attack_vector(self, start_node_id: str, target_node_id: str) -> List[str]:
        """Finds the lowest-friction attack path for an adversary."""
        try:
            return nx.shortest_path(self.graph, source=start_node_id, target=target_node_id, weight="weight")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def identify_chokepoints(self) -> List[str]:
        """
        Identifies architectural chokepoints (articulation points / bridge nodes)
        where breaking a single permission eliminates multiple attack vectors.
        """
        undirected = self.graph.to_undirected()
        return list(nx.articulation_points(undirected))

    def export_mermaid_diagram(self) -> str:
        """Generates visual Mermaid flowchart markdown for reports and dashboards."""
        lines = ["flowchart LR"]
        for node_id, data in self.nodes_data.items():
            critical_marker = ":::critical" if data.is_critical_asset else ""
            lines.append(f'    {node_id}["{data.resource_type}: {data.name}"]{critical_marker}')

        for u, v, attrs in self.graph.edges(data=True):
            action = attrs.get("action", "pivot")
            mitre = attrs.get("mitre", "")
            label = f"{action}\\n({mitre})" if mitre else action
            lines.append(f'    {u} -->|"{label}"| {v}')

        lines.append("    classDef critical fill:#ff4d4f,stroke:#fff,stroke-width:2px,color:#fff;")
        return "\n".join(lines)
