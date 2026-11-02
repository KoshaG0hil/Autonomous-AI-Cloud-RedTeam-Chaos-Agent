"""
MITRE ATT&CK for Cloud Mapping Engine
Correlates cloud misconfigurations and privilege escalation vectors to standardized ATT&CK tactics & techniques.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    subtechnique: Optional[str] = None
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW


MITRE_CLOUD_CATALOG: Dict[str, MitreTechnique] = {
    "T1078.004": MitreTechnique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        tactic="Initial Access / Defense Evasion",
        description="Adversaries may obtain and abuse credentials of existing cloud accounts.",
        severity="HIGH"
    ),
    "T1552.005": MitreTechnique(
        technique_id="T1552.005",
        name="Unsecured Credentials: Cloud Instance Metadata Service",
        tactic="Credential Access",
        description="Adversaries may query the Instance Metadata Service (IMDSv1) to obtain credentials.",
        severity="CRITICAL"
    ),
    "T1530": MitreTechnique(
        technique_id="T1530",
        name="Data from Cloud Storage",
        tactic="Collection / Exfiltration",
        description="Adversaries may access data objects directly from cloud storage buckets lacking strict authorization.",
        severity="HIGH"
    ),
    "T1098.001": MitreTechnique(
        technique_id="T1098.001",
        name="Account Manipulation: Additional Cloud Credentials",
        tactic="Persistence / Privilege Escalation",
        description="Adversaries may create additional access keys or login profiles to retain persistence.",
        severity="CRITICAL"
    ),
    "T1548.005": MitreTechnique(
        technique_id="T1548.005",
        name="Abuse Elevation Control Mechanism: Temporary Elevated Cloud Privileges",
        tactic="Privilege Escalation",
        description="Adversaries abuse STS AssumeRole or wildcard IAM policies to hop between trust boundaries.",
        severity="CRITICAL"
    ),
    "T1580": MitreTechnique(
        technique_id="T1580",
        name="Cloud Infrastructure Discovery",
        tactic="Discovery",
        description="Adversaries may enumerate resources, IAM roles, and storage services to plan exploitation.",
        severity="MEDIUM"
    ),
    "T1562.001": MitreTechnique(
        technique_id="T1562.001",
        name="Impair Defenses: Disable Cloud Logs",
        tactic="Defense Evasion",
        description="Adversaries may disable CloudTrail or delete logging buckets to avoid forensic attribution.",
        severity="CRITICAL"
    )
}


class MitreMapper:
    """Matches cloud reconnaissance findings to MITRE ATT&CK techniques."""

    @staticmethod
    def map_finding(finding_type: str) -> Optional[MitreTechnique]:
        mapping = {
            "imdsv1_enabled": MITRE_CLOUD_CATALOG["T1552.005"],
            "s3_public_read": MITRE_CLOUD_CATALOG["T1530"],
            "s3_unencrypted": MITRE_CLOUD_CATALOG["T1530"],
            "iam_wildcard_admin": MITRE_CLOUD_CATALOG["T1098.001"],
            "iam_assumerole_chain": MITRE_CLOUD_CATALOG["T1548.005"],
            "cloudtrail_disabled": MITRE_CLOUD_CATALOG["T1562.001"],
            "security_group_open_ingress": MITRE_CLOUD_CATALOG["T1078.004"],
            "unrestricted_discovery": MITRE_CLOUD_CATALOG["T1580"]
        }
        return mapping.get(finding_type)

    @staticmethod
    def get_all_techniques() -> List[MitreTechnique]:
        return list(MITRE_CLOUD_CATALOG.values())
