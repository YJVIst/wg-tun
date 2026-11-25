import base64
import io
from contextlib import redirect_stdout
from subprocess import CompletedProcess
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import manager as m

KEY = base64.b64encode(bytes(range(32))).decode()
TEXT = f"[Interface]\nAddress = 10.1.2.3/32,fd01::1/128\nPrivateKey = {KEY}\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {KEY}\nAllowedIPs = 0.0.0.0/0,::/0\nEndpoint = [2001:db8::1]:51820\n"
class ConfigTests(unittest.TestCase):
    def test_families(self):
        addrs, routes, mtu, dns, wire = m.config(TEXT.encode())
        self.assertEqual([a.version for a in addrs], [4,6])
        self.assertEqual(len(routes), 2)
        self.assertEqual((mtu,dns), (1420,['1.1.1.1']))
        self.assertNotIn(b'Address',wire)
        self.assertNotIn(b'DNS',wire)
        self.assertIn(b'FwMark',wire)
    def test_directives_ports_keys_and_duplicate_peers(self):
        for raw in [TEXT+'PostUp = false\n',TEXT.replace(KEY,'invalid',1),
                    TEXT.replace('51820','65536'),TEXT.replace(',fd01::1/128',''),
                    TEXT+TEXT[TEXT.index('[Peer]'):],TEXT.replace('::/0','0.0.0.0/0')]:
            with self.subTest():
                with self.assertRaises((ValueError,m.Problem)):
                    m.config(raw.encode())
    def test_mtu_preserves_other_fields_and_limits(self):
        crlf = b'\xef\xbb\xbf' + TEXT.replace('\n', '\r\n').encode()
        inserted = m.with_mtu(crlf, '1350')
        self.assertEqual(inserted.replace(b'MTU = 1350\r\n', b''), crlf)
        commented = inserted.replace(b'MTU = 1350', b'  MTU = 1350  # path')
        self.assertEqual(m.with_mtu(commented, '1280'), commented.replace(b'1350', b'1280'))
        for value in ('1279', '9001', '-9', '1280.0', '1280\nPostUp=true'):
            with self.assertRaises(m.Problem):
                m.with_mtu(crlf, value)
        v4 = TEXT.replace(',fd01::1/128', '').replace(',::/0', '').encode()
        self.assertEqual(m.config(m.with_mtu(v4, '576'))[2], 576)

    def test_rule_order(self):
        for family in (4,6):
            specs=m.rules(family)
            self.assertIn('nop',specs[0])
            self.assertIn('sport',specs[1])
            self.assertIn('dport',specs[2])
            self.assertIn('fwmark',specs[3])
            self.assertIn(m.TABLE,specs[-1])
    def test_enable_with_valid_profile(self):
        with patch.object(m, 'profile', return_value=TEXT.encode()), patch.object(m, 'call') as system:
            m.dispatch('enable', [])
            system.assert_called_once_with('systemctl', 'enable', m.UNIT)

    def test_egress_query_is_family_specific(self):
        with patch.object(m.shutil, 'which', return_value='/usr/bin/curl'), patch.object(m, 'call') as fetch:
            for family, answer, expected in ((4, b'1.1.1.1', '1.1.1.1'),
                                             (6, b'2606:4700:4700::1111', '2606:4700:4700::1111'),
                                             (6, b'1.1.1.1', '未能测得'),
                                             (4, b'10.0.0.1', '未能测得'),
                                             (4, b'<html>', '未能测得')):
                fetch.return_value = CompletedProcess([], 0, answer)
                self.assertEqual(m.public_ip(family), expected)
                self.assertIn(f'-{family}', fetch.call_args.args)
            fetch.return_value = CompletedProcess([], 28, b'')
            self.assertEqual(m.public_ip(6), '未能测得')

    def test_overview_contains_only_public_configuration(self):
        raw = (TEXT + 'PresharedKey = ' + KEY + '\n').encode()
        with patch.object(m, 'PROFILE') as path, patch.object(m, 'profile', return_value=raw), patch.object(m, 'active', return_value='active'):
            path.name = 'tunnel.conf'
            path.exists.return_value = True
            output = io.StringIO()
            with redirect_stdout(output):
                m.menu_overview()
            self.assertNotIn(KEY, output.getvalue())
            self.assertIn('[2001:db8::1]:51820', output.getvalue())
            self.assertIn('IPv6 全隧道', output.getvalue())

if __name__=='__main__':
    unittest.main()
