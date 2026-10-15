
from agents.agent_trivy import TrivyAgent


def test_trivy_normalize_merges_cves_and_fix_version():
    agent = TrivyAgent()
    raw = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "PkgName": "cryptography",
                        "InstalledVersion": "3.4.8",
                        "VulnerabilityID": "CVE-2023-50782",
                        "Severity": "HIGH",
                        "FixedVersion": "42.0.0",
                    },
                    {
                        "PkgName": "cryptography",
                        "InstalledVersion": "3.4.8",
                        "VulnerabilityID": "CVE-2026-26007",
                        "Severity": "MEDIUM",
                        "FixedVersion": "46.0.5",
                    },
                    {
                        "PkgName": "cryptography",
                        "InstalledVersion": "3.4.8",
                        "VulnerabilityID": "{CVE-2021-23437,CVE-2021-34552}",
                        "Severity": "LOW",
                        "FixedVersion": "41.0.0",
                    },
                ]
            }
        ]
    }

    findings = agent._normalize(raw)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["package"] == "cryptography"
    assert finding["version"] == "3.4.8"
    assert finding["fix_version"] == "46.0.5"
    assert finding["cve_id"] == ["CVE-2021-23437", "CVE-2021-34552", "CVE-2023-50782", "CVE-2026-26007"]
    assert finding["severity"] == "HIGH"
