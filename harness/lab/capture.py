"""Wait for capture readiness and a flushed, acknowledged shutdown.

Only the named experiment container is touched. No model command is executed by
this module. tcpdump diagnostics are saved next to the pcap as audit evidence.
"""
import re
import time
from pathlib import Path


class Capture:
    def __init__(self, docker, container, prefix='/capture/session'):
        self.docker = docker
        self.container = container
        self.prefix = prefix

    def read(self, suffix):
        return self.docker('exec', self.container, 'cat', self.prefix + suffix,
                           check=False).stdout

    def start(self):
        p = self.prefix
        self.docker('exec', self.container, 'rm', '-f',
                    *[p+s for s in ('.pcap', '.log', '.pid', '.done')])
        # Immediate mode avoids the buffered tail loss seen in the old pilot.
        command = (f'tcpdump --immediate-mode -n -i eth0 -s0 -U -B 4096 '
                   f'-w {p}.pcap "ip and net 172.30.0.0/24" 2>{p}.log & '
                   f'pid=$!; echo "$pid" >{p}.pid; wait "$pid"; '
                   f'code=$?; sync {p}.pcap; echo "$code" >{p}.done')
        self.docker('exec', '-d', self.container, 'sh', '-c', command)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.read('.done').strip():
                raise RuntimeError('tcpdump exited during startup: ' + self.read('.log'))
            if 'listening on eth0' in self.read('.log'):
                return
            time.sleep(.1)
        raise RuntimeError('tcpdump did not acknowledge readiness')

    def stop(self, destination):
        pid = self.read('.pid').strip()
        if not pid.isdigit():
            raise RuntimeError('Missing capture PID; refusing a broad pkill')
        self.docker('exec', self.container, 'kill', '-INT', pid, check=False)
        deadline = time.monotonic() + 10
        done = ''
        while time.monotonic() < deadline:
            done = self.read('.done').strip()
            if done:
                break
            time.sleep(.1)
        if not done:
            raise RuntimeError('tcpdump shutdown not acknowledged; pcap not accepted')
        log = self.read('.log')
        destination = Path(destination)
        self.docker('cp', self.container+':'+self.prefix+'.pcap', str(destination))
        destination.with_suffix('.capture.log').write_text(log)
        dropped = re.search(r'(\d+) packets dropped by kernel', log)
        captured = re.search(r'(\d+) packets captured', log)
        issues = []
        if done != '0':
            issues.append('tcpdump_exit:' + done)
        if dropped is None or captured is None:
            issues.append('missing_capture_counters')
        elif int(dropped[1]):
            issues.append('kernel_packet_loss')
        return {'implementation': 'acknowledged-immediate-v3', 'exit_code': done,
                'kernel_drops': int(dropped[1]) if dropped else None,
                'packets_captured': int(captured[1]) if captured else None,
                'issues': issues}
