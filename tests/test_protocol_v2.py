import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
import dpkt

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'harness'),str(ROOT/'harness/lab')]
from eval_common import wilson, train_vocab, sequence, threshold_from_negatives
from recon_features import features
from driver import operator_prompt


def packet(src,dst,sport,dport,flags):
    tcp=dpkt.tcp.TCP(sport=sport,dport=dport,flags=flags)
    ip=dpkt.ip.IP(src=ipaddress.ip_address(src).packed,dst=ipaddress.ip_address(dst).packed,
                  p=6,data=tcp)
    ip.len=len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=0x800,data=ip))

class ProtocolTests(unittest.TestCase):
    def test_reply_ephemeral_port_does_not_expand_scan_scope(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'test.pcap'
            with p.open('wb') as f:
                w=dpkt.pcap.Writer(f)
                w.writepkt(packet('172.30.0.10','172.30.0.11',54321,80,2),ts=1)
                w.writepkt(packet('172.30.0.11','172.30.0.10',80,54321,20),ts=2)
                # Unrelated DNS / public traffic does not count toward lab scope.
                w.writepkt(packet('172.30.0.10','8.8.8.8',54322,53,2),ts=3)
            v=features(p)
            self.assertEqual(v['unique_dst_ports'],1)
            self.assertEqual(v['port_span'],0)
            self.assertEqual(v['unique_dst_ips'],1)
            self.assertEqual(v['rst_recv_frac'],1)
            self.assertEqual(v['n_syn'],1)
            self.assertEqual(v['n_pkts'],2)
    def test_zero_traffic_is_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'empty.pcap'
            with p.open('wb') as f:
                dpkt.pcap.Writer(f)
            self.assertEqual(features(p)['zero_traffic'],1)
    def test_perfect_small_sample_is_uncertain(self):
        lo,hi=wilson([1,1,1])
        self.assertLess(lo,.5)
        self.assertAlmostEqual(hi,1)
    def test_vocabulary_cannot_see_test_tokens(self):
        rows=[{'origin':'ai','cmds':['pwd','cat x','ls']},
              {'origin':'human','cmds':['cat y','ls','ssh x']}]
        v=train_vocab(rows)
        self.assertEqual(v,{'cat','ls'})
        self.assertEqual(sequence({'cmds':['secret','cat z']},v),['cat'])
    def test_no_prompt_induced_recovery_command(self):
        for name in ('prompt_1','prompt_3','prompt_5','ctf_recon','ctf_exploit','ctf_crack','benign_1','benign_2','benign_3'):
            self.assertNotIn('pwd',operator_prompt(name))
        self.assertIn('pwd',operator_prompt('prompt_1',legacy=True))
    def test_low_fpr_threshold_uses_calibration_negatives(self):
        self.assertGreater(threshold_from_negatives([.1,.2,.8],.01),.8)


class DriverTests(unittest.TestCase):
    def test_repeated_command_is_not_replaced(self):
        from unittest.mock import MagicMock,patch
        import driver
        channel=MagicMock()
        channel.recv_ready.return_value=False
        client=MagicMock()
        client.invoke_shell.return_value=channel
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'session.json'
            with patch.object(driver.paramiko,'SSHClient',return_value=client), patch.object(driver.time,'sleep'), patch.object(driver,'ask_model',side_effect=['ls','ls']):
                driver.run_session('mock','lab','prompt_1','localhost',22,'u','p',2,out)
            import json
            rows=json.loads(out.read_text())
            self.assertEqual([t[0][0] for t in rows[1:]],['ls','ls'])
            self.assertEqual([t[3][1]['rewritten'] for t in rows[1:]],[False,False])
    def test_empty_response_executes_nothing(self):
        from unittest.mock import MagicMock,patch
        import driver
        channel=MagicMock(); channel.recv_ready.return_value=False
        client=MagicMock(); client.invoke_shell.return_value=channel
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'session.json'
            with patch.object(driver.paramiko,'SSHClient',return_value=client), patch.object(driver.time,'sleep'), patch.object(driver,'ask_model',return_value=''):
                driver.run_session('mock','lab','prompt_1','localhost',22,'u','p',2,out)
            channel.send.assert_not_called()
            import json
            self.assertIsNone(json.loads(out.read_text())[1][3][1]['executed'])

class TransportTests(unittest.TestCase):
    def test_direction_does_not_depend_on_numerical_port_order(self):
        sys.path.insert(0,str(ROOT/'harness/net'))
        from pcap_features import load_flows
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ssh.pcap'
            with p.open('wb') as f:
                w=dpkt.pcap.Writer(f)
                w.writepkt(packet('127.0.0.1','127.0.0.2',1024,65000,2),ts=1)
                tcp=dpkt.tcp.TCP(sport=1024,dport=65000,flags=24,data=b'SSH-test')
                ip=dpkt.ip.IP(src=ipaddress.ip_address('127.0.0.1').packed,dst=ipaddress.ip_address('127.0.0.2').packed,p=6,data=tcp)
                ip.len=len(ip)
                w.writepkt(bytes(dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=0x800,data=ip)),ts=2)
            self.assertTrue(load_flows(p)[0][-1])

if __name__ == "__main__": unittest.main()
