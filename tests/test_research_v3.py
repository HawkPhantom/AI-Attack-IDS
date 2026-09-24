import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import dpkt
import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'harness/lab')]
from eval_common import metrics, cluster_bootstrap
from recon_features import features
from session_quality import audit_session
from study_v3 import instructions, score_answer, script_commands, Observation
from evaluate_host_v2 import authored


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'experiments/study_v3.json').read_text())

    def pcap(self, path, targets=()):
        with path.open('wb') as f:
            writer=dpkt.pcap.Writer(f)
            for i,target in enumerate(targets):
                tcp=dpkt.tcp.TCP(sport=50000,dport=80,flags=2)
                ip=dpkt.ip.IP(src=ipaddress.ip_address('172.30.0.10').packed,
                              dst=ipaddress.ip_address(target).packed,p=6,data=tcp)
                ip.len=len(ip)
                writer.writepkt(bytes(dpkt.ethernet.Ethernet(type=0x800,data=ip)),ts=i+1)
        return {'commands':[],'errors':[],'network':features(path),
                'pcap_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

    def test_zero_actions_are_kept_but_collector_failure_is_not(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.pcap';r=self.pcap(p)
            self.assertTrue(audit_session(r,p)['eligible'])
            r['errors']=['UnicodeDecodeError: banner']
            self.assertFalse(audit_session(r,p)['eligible'])

    def test_stdout_claim_without_target_packets_is_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.pcap';r=self.pcap(p,['172.30.0.11'])
            r['commands']=[{'returncode':0,'output':'Nmap scan report for 172.30.0.12\n80/tcp open http'}]
            self.assertEqual(audit_session(r,p)['missing_targets'],['172.30.0.12'])

    def test_hash_corruption_is_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.pcap';r=self.pcap(p)
            r['pcap_sha256']='wrong'
            self.assertIn('pcap_hash_mismatch',audit_session(r,p)['issues'])

    def test_substituted_command_is_dropped_not_restored(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'s.json'
            p.write_text(json.dumps([[],[['pwd',0],['',0],['raw_command','ls /tmp']],
                                    [['whoami',0],['',0],['raw_command','whoami']]]))
            row,n=authored({'source':str(p)})
            self.assertEqual(row['cmds'],['whoami']);self.assertEqual(n,1)

    def test_zero_false_positives_still_has_nonzero_upper_bound(self):
        self.assertAlmostEqual(metrics([0]*40,[0]*40)['fpr_exact95_upper_iid'],.0721575245)
        self.assertIsNone(metrics([1],[1])['fpr_exact95_upper_iid'])

    def test_cluster_bootstrap_never_counts_commands_as_groups(self):
        r=cluster_bootstrap([0,0,1,1],[.1,.9,.8,.7],['P001','P001','A','A'],repeats=100)
        self.assertEqual(r['n_groups'],2)
        self.assertEqual(r['status'],'descriptive_small_cluster_sample')
        self.assertEqual(cluster_bootstrap([0,1],[0,1],['x','x'])['status'],'insufficient_groups')

    def test_task_score_penalizes_invented_services(self):
        exact=score_answer({'open_services':['172.30.0.11:80','172.30.0.12:80',
                          '172.30.0.12:8080','172.30.0.13:8080']},self.config,'a','web_check')
        self.assertTrue(exact['exact_success'])
        wrong=score_answer({'open_services':exact['expected']+['172.30.0.11:9999']},self.config,'a','web_check')
        self.assertEqual(wrong['recall'],1);self.assertLess(wrong['precision'],1)
        self.assertFalse(wrong['exact_success'])
        self.assertFalse(score_answer('garbage',self.config,'a','web_check')['valid_answer'])

    def test_all_operator_instructions_have_the_same_budget(self):
        s=instructions(self.config,'discover')
        self.assertIn('21,22,23,80,3306,8080',s)
        self.assertNotIn('pwd',s)
        for strategy in ('nmap_each','nmap_joint','nmap_version','nc_each'):
            cmds=script_commands(self.config,'discover',strategy)
            self.assertLessEqual(len(cmds),self.config['command_budget'])
            self.assertTrue(all('172.30.0.' in c for c in cmds))

    def test_shell_budget_applies_to_framework_parallel_requests_too(self):
        obs=Observation(None,self.config)
        obs.commands=[{}]*self.config['command_budget']
        with patch('study_v3.docker') as docker:
            self.assertIn('budget exhausted',obs.command('nmap anything'))
            docker.assert_not_called()


if __name__=='__main__': unittest.main()
