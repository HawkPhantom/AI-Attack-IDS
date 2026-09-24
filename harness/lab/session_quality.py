"""Measurement failures are quarantined, operator failures remain observations."""
import hashlib
import re
from pathlib import Path
from recon_features import features, parse


# Docker/executor transport failures are measurement errors, not operator outcomes.
TRANSPORT = re.compile(r'No such container|Error response from daemon|'
                       r'Cannot connect to the Docker daemon', re.I)
# Positive evidence that a command actually reached a lab target.
CONTACT = re.compile(r'\d+/tcp\s+(?:open|closed)\b|Host is up|'
                     r'bytes from 172\.30\.0\.(?:11|12|13)|'
                     r'Connection to 172\.30\.0\.(?:11|12|13)\b')


def audit_session(row, pcap):
    issues = []
    if row.get('errors'):
        issues.append('collector_error')
    if (row.get('capture') or {}).get('issues'):
        issues.extend(row['capture']['issues'])
    # A daemon/executor error in any command output is a transport failure even
    # when docker exec returned it as ordinary output under check=False.
    if any(TRANSPORT.search(c.get('output', '') or '') for c in row.get('commands', [])):
        issues.append('collector_transport_error')
    pcap = Path(pcap)
    if not pcap.exists():
        return {'eligible': False, 'issues': issues+['missing_pcap']}
    if row.get('pcap_sha256') != hashlib.sha256(pcap.read_bytes()).hexdigest():
        issues.append('pcap_hash_mismatch')
    try:
        fresh = features(pcap)
        if any(fresh.get(k) != v for k, v in row.get('network', {}).items()):
            issues.append('feature_mismatch')
        observed = {e[2] for e in parse(pcap) if e[5]}
        expected = set()
        contacted = False
        for command in row.get('commands', []):
            output = command.get('output', '') or ''
            if CONTACT.search(output):
                contacted = True
            if command.get('returncode') != 0:
                continue
            if re.search(r'\d+/tcp\s+(?:open|closed)\b', output):
                for line in output.splitlines():
                    if line.startswith('Nmap scan report for '):
                        expected.update(re.findall(r'172\.30\.0\.(?:11|12|13)\b', line))
        missing = sorted(expected-observed)
        if missing:
            issues.append('output_target_missing_from_pcap')
        # A session that demonstrably reached a target but captured no packets is
        # an incomplete capture, regardless of hash match or zero kernel drops.
        captured = (row.get('capture') or {}).get('packets_captured')
        if contacted and captured == 0:
            issues.append('activity_without_capture')
    except (ValueError, OSError) as error:
        return {'eligible': False, 'issues': issues+['unreadable_pcap'],
                'detail': str(error)}
    return {'eligible': not issues, 'issues': issues,
            'output_targets': sorted(expected), 'pcap_targets': sorted(observed),
            'missing_targets': missing, 'reached_target': contacted,
            'capture_counters_available': bool(row.get('capture'))}
