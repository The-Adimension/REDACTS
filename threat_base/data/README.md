# Knowledge Data Directory

## Integrity

Two integrity mechanisms protect different file categories:

1. **`checksums.json`** - SHA-256 manifest for **shipped** YAML files.
   Verified at load time by `data_loader.py`. Refreshed by `python main.py update all`.

2. **`.sha256` sidecars** - SHA-256 for **downloaded** files (ATT&CK bundle,
   CWE CSV, YARA rules). Written at download time, verified on subsequent loads.

## Provenance

See **`sources.json`** for the complete provenance manifest: URLs, versions,
licenses, and attribution for every knowledge data source.

## Files

### Shipped with REDACTS (in `yaml/`)

| File | Purpose |
|------|---------|
| `attack_vectors.yaml` | 34 filesystem-detectable attack vectors |
| `infinitered_campaign.yaml` | INFINITERED campaign indicators |
| `ioc_indicators.yaml` | Indicators of compromise |
| `mitre_mapping.yaml` | ATT&CK / CVSS / CWE mappings |
| `redcap_baseline.yaml` | Known-good REDCap directory structure |
| `security_rules.yaml` | PHP vulnerability detection rules |
| `sensitive_data_patterns.yaml` | PHI / PII / credential patterns |

### Downloaded at Runtime

| File | Source | License |
|------|--------|---------|
| `enterprise-attack.json` | [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) v18.1 | Apache-2.0 |
| `cwec_v*.csv` | [cwe.mitre.org](https://cwe.mitre.org/data/csv/) | CWE Terms of Use |

## Update Procedure

```bash
python main.py update all       # Update all knowledge sources
python main.py update cwe       # CWE database only
python main.py update attack    # ATT&CK Enterprise only
python main.py update yara      # YARA community rules only
python main.py update nvd       # Validate NVD API configuration
```

## Air-Gapped Environments

For systems without internet access, pre-download the data on a connected machine
and copy the files into this directory before running the scan.
