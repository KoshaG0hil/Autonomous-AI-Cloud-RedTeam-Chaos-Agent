"""
Autonomous AI Cloud Red-Team & Chaos Adversary Engine - Interactive CLI
"""

import sys
import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from core.agent import AutonomousRedTeamAgent

console = Console()


def generate_benchmark_findings():
    """Generates a realistic multi-hop cloud compromise benchmark scenario."""
    return [
        {
            "finding_type": "security_group_open_ingress",
            "source_id": "Internet_Perimeter",
            "source_type": "NETWORK",
            "source_name": "Public Ingress 0.0.0.0/0",
            "target_id": "EC2_Edge_Bastion",
            "target_type": "EC2",
            "target_name": "Web Proxy EC2 Instance",
            "exploit_action": "EXPLOIT_PUBLIC_EXPOSURE",
            "cost": 1.0
        },
        {
            "finding_type": "imdsv1_enabled",
            "source_id": "EC2_Edge_Bastion",
            "source_type": "EC2",
            "source_name": "Web Proxy EC2 Instance",
            "target_id": "Role_AppDeployment",
            "target_type": "IAM_ROLE",
            "target_name": "AppDeploymentInstanceProfileRole",
            "exploit_action": "IMDS_SSRF_TOKEN_THEFT",
            "cost": 1.5
        },
        {
            "finding_type": "s3_public_read",
            "source_id": "Role_AppDeployment",
            "source_type": "IAM_ROLE",
            "source_name": "AppDeploymentInstanceProfileRole",
            "target_id": "S3_Backup_Bucket",
            "target_type": "S3_BUCKET",
            "target_name": "corporate-database-backups",
            "exploit_action": "S3_CREDENTIAL_EXTRACTION",
            "cost": 1.2
        },
        {
            "finding_type": "iam_wildcard_admin",
            "source_id": "S3_Backup_Bucket",
            "source_type": "S3_BUCKET",
            "source_name": "corporate-database-backups",
            "target_id": "Crown_Jewel_Admin",
            "target_type": "ADMIN",
            "target_name": "IAM Administrator Access & Customer Secrets",
            "exploit_action": "PRIVILEGE_ESCALATION_ADMIN",
            "is_critical": True,
            "cost": 0.8
        }
    ]


def run_cli():
    console.print(Panel.fit(
        "[bold red]AUTONOMOUS AI CLOUD RED-TEAM & CHAOS ADVERSARY ENGINE[/bold red]\n"
        "[cyan]Agentic Attack Path Synthesis · Blast Radius Analysis · Self-Healing Remediation[/cyan]",
        border_style="red"
    ))

    with console.status("[bold yellow]Ingesting cloud telemetry and building directed attack graph..."):
        agent = AutonomousRedTeamAgent(target_environment="AWS-Production-Cluster")
        findings = generate_benchmark_findings()
        agent.ingest_telemetry_findings(findings)
        result = agent.run_autonomous_simulation()

    # 1. Adversary Emulation Log
    console.print("\n[bold green]=== ADVERSARY REASONING & ATTACK SIMULATION LOG ===[/bold green]")
    log_table = Table(show_header=True, header_style="bold magenta")
    log_table.add_column("Step", style="dim", width=6)
    log_table.add_column("Action Taken", width=26)
    log_table.add_column("Target Asset", width=25)
    log_table.add_column("MITRE Technique", width=18)
    log_table.add_column("Status", width=12)

    for step in result["execution_log"]:
        log_table.add_row(
            str(step["step_number"]),
            f"[bold yellow]{step['action']}[/bold yellow]",
            step["target"],
            f"[cyan]{step['mitre_technique']}[/cyan]",
            f"[bold red]{step['status']}[/bold red]"
        )
    console.print(log_table)

    # 2. Blast Radius Scorecard
    br = result["blast_radius"]
    console.print("\n[bold red]=== QUANTITATIVE BLAST RADIUS METRICS ===[/bold red]")
    br_table = Table(show_header=True, header_style="bold cyan")
    br_table.add_column("Metric", width=35)
    br_table.add_column("Value", width=25)

    br_table.add_row("Total Viable Attack Paths to Crown Jewel", str(result["attack_paths_count"]))
    br_table.add_row("Shortest Compromise Vector (Hops)", str(br["shortest_hops"]))
    br_table.add_row("Environment Reachability (%)", f"{br['reachability_pct']}%")
    br_table.add_row("Crown Jewel Compromised", "[bold red]YES[/bold red]" if br["target_exposed"] else "[green]NO[/green]")
    br_table.add_row("Blast Radius Severity Index", f"[bold red]{br['blast_radius_index']} / 100[/bold red]")
    console.print(br_table)

    # 3. Chokepoints
    if result["chokepoints"]:
        console.print(f"\n[bold yellow][!] Identified Architectural Chokepoint Assets:[/bold yellow] {', '.join(result['chokepoints'])}")

    # 4. Self-Healing Terraform Patches
    console.print("\n[bold green]=== AUTONOMOUS SELF-HEALING TERRAFORM PATCHES ===[/bold green]")
    for patch in result["remediation_patches"][:2]:
        console.print(f"\n[bold cyan]> {patch['title']}[/bold cyan] - [dim]{patch['description']}[/dim]")
        syntax = Syntax(patch["terraform"], "terraform", theme="monokai", line_numbers=True)
        console.print(syntax)

    console.print("\n[bold green][SUCCESS] Autonomous Simulation Complete: All attack vectors mapped and patches synthesized.[/bold green]\n")


if __name__ == "__main__":
    run_cli()
