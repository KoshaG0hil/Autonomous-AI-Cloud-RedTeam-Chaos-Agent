"""
Blast Radius & Risk Scorer
Computes quantitative compromise severity, graph reachability, and risk scores.
"""

from typing import Dict, List
from .attack_graph import AttackGraph


class BlastRadiusCalculator:
    """Calculates quantitative risk and blast radius metrics from the attack graph."""

    @staticmethod
    def calculate_score(
        attack_graph: AttackGraph,
        compromised_entry_node: str,
        critical_target_node: str
    ) -> Dict[str, float]:
        """
        Calculates:
        1. Reachability Percentage (fraction of cloud assets reachable from entry point)
        2. Shortest Hop Count to Crown Jewel
        3. Critical Asset Exposure (Boolean/Severity)
        4. Overall Blast Radius Index (0 - 100)
        """
        total_nodes = attack_graph.graph.number_of_nodes()
        if total_nodes == 0 or not attack_graph.graph.has_node(compromised_entry_node):
            return {
                "reachability_pct": 0.0,
                "shortest_hops": 0,
                "target_exposed": False,
                "blast_radius_index": 0.0
            }

        paths = attack_graph.find_all_attack_paths(compromised_entry_node, critical_target_node)
        target_exposed = len(paths) > 0

        # Reachable descendants
        reachable_nodes = len(list(attack_graph.graph.successors(compromised_entry_node)))
        reachability_pct = round((reachable_nodes / max(1, total_nodes - 1)) * 100, 2)

        shortest_path = attack_graph.get_shortest_attack_vector(compromised_entry_node, critical_target_node)
        shortest_hops = len(shortest_path) - 1 if shortest_path else 999

        # Scoring algorithm:
        # High base if crown jewel exposed, penalized more if hops are few
        base_score = 60.0 if target_exposed else 10.0
        hop_penalty = max(0.0, (10 - shortest_hops) * 3.5) if target_exposed else 0.0
        reach_factor = reachability_pct * 0.25

        blast_index = min(100.0, round(base_score + hop_penalty + reach_factor, 1))

        return {
            "reachability_pct": reachability_pct,
            "shortest_hops": shortest_hops if shortest_hops != 999 else -1,
            "target_exposed": target_exposed,
            "total_attack_vectors": len(paths),
            "blast_radius_index": blast_index
        }
