"""Reproduce synthetic outputs only; never contact a bank or scan a network.

python docs/readiness-evidence/bank-original45-2026-10-24/reproduce-sample.py /external/output
"""
from pathlib import Path
import json
import sys
from datetime import date

ROOT = Path(__file__).resolve().parents[3]
for path in ('services/cbom', 'services/quantum', 'shared/shared_models'):
    sys.path.insert(0, str(ROOT / path))
from cbom.generator import CbomGenerator
from cbom.cyclonedx16 import validate_cyclonedx16
from quantum.plan import build_migration_plan


def main():
    if len(sys.argv) != 2:
        raise SystemExit('Specify an external output directory; retained records must not be overwritten')
    output = Path(sys.argv[1]).resolve()
    retained = ROOT / 'docs/examples/bank-pqc-discovery'
    if output.is_relative_to(retained):
        raise SystemExit('Refusing to overwrite retained example outputs')
    output.mkdir(parents=True, exist_ok=True)
    fixture = json.loads((retained / 'inputs.json').read_text())
    generator = CbomGenerator()
    bom = generator.from_records(fixture['records'], name='SYNTHETIC-BANK-NOT-A-CUSTOMER',
        version=fixture['fixture'], spec_version='1.6', scan_id=fixture['fixture'])
    bom['metadata']['timestamp'] = '2026-10-24T00:00:00Z'  # fixture time, not scan observation time
    check = validate_cyclonedx16(bom)
    if not check['ok']:
        raise SystemExit(check)
    report = {'fixture': fixture['fixture'], 'bank_approved': False, 'customer_evidence': False,
        'scanner_executed': False, 'supplied_records': len(fixture['records']),
        'exported_crypto_components': len(bom['components']), 'validation': check,
        'qualification': 'SYNTHETIC_INPUT_EXPORT_AND_PLANNING_ONLY',
        'omitted': ['key values', 'certificate bodies', 'runtime/deployment proof', 'independent completeness',
                    'bank references', 'real protocol/latency/packet/certificate/HSM performance'],
        'migration_plan': build_migration_plan(fixture['records'], systems=fixture['systems'], today=date(2026, 10, 24))}
    (output / 'cbom.cyclonedx16.json').write_text(generator.to_json(bom)+'\n')
    (output / 'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'schema_valid': check['ok'], 'supplied': len(fixture['records']),
                      'exported': len(bom['components']), 'bank_approved': False}))


if __name__ == '__main__':
    main()
