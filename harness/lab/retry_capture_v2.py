#!/usr/bin/env python3
"""Archive collector decoding failures and repeat them with fixed UTF-8 handling.

Does not retry model refusals, empty commands, or tool failures to select success.
"""
import json
from pathlib import Path
from collect_v2 import ROOT,setup,cleanup,session

def main():
    root=ROOT/'harness/runs/corrected_v2'
    todo=[]
    for path in sorted(root.glob('*.json')):
        r=json.loads(path.read_text())
        if any(e.startswith('UnicodeDecodeError:') for e in r.get('errors',[])):
            todo.append((path,r))
    archive=root/'collector_failures'
    archive.mkdir(exist_ok=True)
    manifest_path=ROOT/'experiments/collector_retries.json'
    manifest=json.loads(manifest_path.read_text()) if manifest_path.exists() else []
    for env in sorted({r['env'] for _,r in todo}):
        setup(env)
        try:
            for path,r in todo:
                if r['env']!=env: continue
                # Explicit archival, never silently overwrite failed attempts.
                dest=archive/path.name
                if dest.exists(): raise RuntimeError('Retry archive already exists')
                path.rename(dest); path.with_suffix('.pcap').rename(dest.with_suffix('.pcap'))
                manifest.append({'id':r['id'],'reason':r['errors'],'archived':str(dest.relative_to(ROOT)),
                                 'pcap_sha256':r['pcap_sha256'],'retry_policy':'collector decoding error only'})
                manifest_path.write_text(json.dumps(manifest,indent=2))
                meta={k:r[k] for k in ('origin','model','env','scaffold','task','source_group')}
                if r['origin']!='ai':
                    replay=[c['executed'] for c in r['commands'] if c.get('executed')]
                else: replay=None
                session(root,r['id'],meta,6,replay=replay,seed=r['seed'])
        finally:
            cleanup()
    print(f'Retried {len(todo)} collector failures',flush=True)

if __name__=='__main__': main()
