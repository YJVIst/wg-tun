"""Run on the test node; requires root, upstream.conf, slirp4netns and OpenSSH."""
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

def run(*args, check=True, data=None, timeout=35):
    result = subprocess.run(list(map(str,args)), input=data, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} {args[1:3]} rc={result.returncode}: {result.stderr.decode(errors='replace')[:400]}")
    return result

def spawn(stack, args, log):
    p = subprocess.Popen(list(map(str,args)), stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    def stop():
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
    stack.callback(stop)
    return p

def wait_for(fn, timeout=10):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if fn(): return True
        time.sleep(.2)
    return False

def trial(root, fixture, report):
    unit = 'wgtun-qa-' + str(os.getpid())
    services = Path('/run/systemd/system')
    with tempfile.TemporaryDirectory(prefix=unit, dir='/run') as tmp, contextlib.ExitStack() as stack:
        d=Path(tmp)
        log=stack.enter_context((d/'process.log').open('wb'))
        dut=spawn(stack,['unshare','--mount','--net','--propagation','private','sleep','1200'],log)
        peer=spawn(stack,['unshare','--net','sleep','1200'],log)
        time.sleep(.2)
        assert dut.poll() is None and peer.poll() is None
        enter=['nsenter','-t',str(dut.pid),'-m','-n','--']
        client=['nsenter','-t',str(peer.pid),'-n','--']
        def host(*a,**kw): return run(*enter,*a,**kw)
        def remote(*a,**kw): return run(*client,*a,**kw)
        # The test resolver mount and all route changes are private to the test.
        assert os.readlink(f'/proc/{dut.pid}/ns/mnt')!=os.readlink('/proc/self/ns/mnt')
        assert os.readlink(f'/proc/{dut.pid}/ns/net')!=os.readlink('/proc/self/ns/net')
        # An active host tunnel can supply a bind-mounted resolv.conf.
        # Drop the inherited mount only inside the private test namespace.
        if host('findmnt','-M','/etc/resolv.conf',check=False).returncode == 0:
            assert host('findmnt','-n','-o','PROPAGATION','-T','/etc/resolv.conf').stdout.strip()==b'private'
            host('umount','/etc/resolv.conf')
        slirp=spawn(stack,['slirp4netns','-c','--disable-host-loopback',dut.pid,'uplink'],log)
        assert wait_for(lambda: b'default' in host('ip','route').stdout) and slirp.poll() is None
        host('ip','link','set','lo','up')
        remote('ip','link','set','lo','up')
        host('ip','link','add','mgmt0','type','veth','peer','name','testnic')
        host('ip','link','set','testnic','netns',peer.pid)
        for fn,dev,v4,v6 in [(host,'mgmt0','10.90.0.1/30','fd42:90::1/64'),(remote,'testnic','10.90.0.2/30','fd42:90::2/64')]:
            fn('ip','link','set',dev,'up')
            fn('ip','addr','add',v4,'dev',dev)
            fn('ip','-6','addr','add',v6,'dev',dev,'nodad')
        if fixture in ('synthetic', 'health'):
            host('sysctl','-qw','net.ipv4.conf.all.rp_filter=1','net.ipv4.conf.mgmt0.rp_filter=1')
        # Off-link SSH client, covering replies which could otherwise follow the tunnel default.
        remote('ip','addr','add','198.51.100.9/32','dev','lo')
        remote('ip','-6','addr','add','2001:db8:2::9/128','dev','lo','nodad')
        host('ip','route','add','198.51.100.9/32','via','10.90.0.2')
        host('ip','-6','route','add','2001:db8:2::9/128','via','fd42:90::2','dev','mgmt0')
        for key in ('client','server'):
            run('ssh-keygen','-q','-t','ed25519','-N','','-f',d/key)
        conf=d/'sshd.conf'
        conf.write_text(f"Port 22\nListenAddress 10.90.0.1\nListenAddress fd42:90::1\nHostKey {d}/server\nAuthorizedKeysFile {d}/client.pub\nPidFile {d}/sshd.pid\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin prohibit-password\nStrictModes yes\n")
        sshd=spawn(stack,[*enter,'/usr/sbin/sshd','-D','-e','-f',conf],log)
        time.sleep(.3)
        assert sshd.poll() is None
        ssh=['ssh','-F','/dev/null','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(d/'known_hosts'),'-o','BatchMode=yes','-o','ConnectTimeout=5','-i',d/'client']
        src4=['-b','198.51.100.9']
        dest='root@10.90.0.1'
        master=spawn(stack,[*client,*ssh,*src4,'-M','-N','-S',d/'ctl',dest],log)
        assert wait_for(lambda:(d/'ctl').exists())
        def existing_ssh():
            return remote(*ssh,*src4,'-S',d/'ctl','-O','check',dest,check=False).returncode==0 and remote(*ssh,*src4,'-S',d/'ctl',dest,'echo alive',check=False).stdout.strip()==b'alive' and master.poll() is None
        assert existing_ssh()
        rpc=d/'manager.py'
        rpc.write_text(f"""import sys
from pathlib import Path
sys.path.insert(0,'/usr/local/lib/wg-tun')
import manager as m
m.PROFILE=Path({str(d/'profile')!r})
m.RUN=Path({str(d/'runtime')!r})
m.STATE=m.RUN/'owned.json'
m.UNIT={unit+'.service'!r}
m.main()
""")
        installed=Path('/etc/systemd/system')
        main=(installed/'wg-tun.service').read_text()
        main='\n'.join(l for l in main.splitlines() if not l.startswith(('RuntimeDirectory','ConditionPathExists'))) + '\n'
        ns=' '.join(enter)
        # nsenter requires SYS_ADMIN, SYS_CHROOT and DAC_READ_SEARCH to enter the isolated mount and network namespaces.
        main=main.replace('CapabilityBoundingSet=', 'CapabilityBoundingSet=CAP_SYS_PTRACE CAP_SYS_CHROOT CAP_DAC_READ_SEARCH ')
        main=main.replace('/usr/local/lib/wg-tun/manager.py', f'{ns} /usr/bin/python3 {rpc}')
        if fixture.startswith('upstream'):
            (d/'profile').write_bytes((root/'upstream.conf').read_bytes())
        else:
            server=run('wg','genkey').stdout
            priv=run('wg','genkey').stdout
            pub=run('wg','pubkey',data=priv).stdout.decode().strip()
            pub_server=run('wg','pubkey',data=server).stdout.decode().strip()
            remote('ip','link','add','wire0','type','wireguard')
            remote('wg','set','wire0','private-key','/dev/stdin','listen-port','41513','peer',pub,'allowed-ips','10.79.0.2/32,fd42:79::2/128',data=server)
            remote('ip','addr','add','10.79.0.1/24','dev','wire0')
            remote('ip','-6','addr','add','fd42:79::1/64','dev','wire0','nodad')
            remote('ip','link','set','wire0','up')
            (d/'profile').write_text(f"[Interface]\nAddress=10.79.0.2/32,fd42:79::2/128\nPrivateKey={priv.decode().strip()}\nDNS=1.1.1.1\n[Peer]\nPublicKey={pub_server}\nEndpoint=10.90.0.2:41513\nAllowedIPs=0.0.0.0/0,::/0\n")
        if fixture == 'domain':
            hosts = d/'hosts'
            hosts.write_text("127.0.0.1 localhost\n10.90.0.1 wg-peer.test\n10.90.0.2 wg-peer.test\n")
            host('mount','--bind',hosts,'/etc/hosts')
            assert host('getent','ahosts','wg-peer.test').stdout.split()[0] == b'10.90.0.1'
            file = d/'profile'
            file.write_bytes(file.read_bytes().replace(b'Endpoint=10.90.0.2:', b'Endpoint=wg-peer.test:'))
        (d/'profile').chmod(0o600)
        file=services/(unit+'.service')
        file.write_text(main)
        stack.callback(file.unlink,missing_ok=True)
        run('systemctl','daemon-reload')
        def stop_units():
            run('systemctl','stop',unit+'.service',check=False)
        stack.callback(stop_units)
        def dns():return hashlib.sha256(host('cat','/etc/resolv.conf').stdout).hexdigest()
        initial=dns()
        try:
            host('python3',rpc,'start')
            started=time.monotonic()
            assert existing_ssh()
            link = json.loads(host('ip','-d','-j','link','show','dev','wgtun0').stdout)[0]
            assert link['linkinfo']['info_kind'] == 'wireguard'
            assert run('systemctl','show','-p','MainPID','--value',unit).stdout.strip() == b'0'
            report['backend'] = 'kernel wireguard'
            report['serviceMainPID'] = 0
            report['existingSSH']=True
            for family,src,addr in [(4,src4[1],'10.90.0.1'),(6,'2001:db8:2::9','fd42:90::1')]:
                assert remote(*ssh,'-b',src,'-S','none','root@'+addr,'echo fresh').stdout.strip()==b'fresh'
                report['newSSH'+str(family)]=True
                def route(dst,*args):return host('ip','-'+str(family),'-j','route','get',dst,*args).stdout
                assert json.loads(route(src,'ipproto','tcp','sport','22','dport','45000'))[0]['dev']=='mgmt0'
                assert json.loads(route(src,'ipproto','tcp','sport','45000','dport','22'))[0]['dev']=='mgmt0'
                assert json.loads(route(src,'mark','0x40000000'))[0]['dev']=='wgtun0'
            if fixture == 'synthetic':
                helper = Path(__file__).resolve().with_name('flow_trial.py')
                for family, client_ip, native, upstream, expected in [
                    (4, '198.51.100.9', '10.90.0.1', '10.79.0.1', '10.79.0.2'),
                    (6, '2001:db8:2::9', 'fd42:90::1', 'fd42:79::1', 'fd42:79::2'),
                ]:
                    for proto in ('tcp', 'udp'):
                        def listen(namespace, role, addr, *target):
                            ready = d/f'{role}-{family}-{proto}'
                            proc = spawn(stack, [*namespace, 'python3', helper, role, proto, addr, ready, *target], log)
                            assert wait_for(lambda: ready.exists() and ready.stat().st_size)
                            return proc, ready.read_text()
                        sink, sink_port = listen(client, 'upstream', upstream)
                        proxy, port = listen(enter, 'proxy', '::' if family == 6 else '0.0.0.0', upstream, sink_port)
                        result = remote('python3', helper, 'client', proto, client_ip, native, port)
                        assert result.stdout.decode().strip() == expected + ' return-path'
                        assert proxy.wait(3) == sink.wait(3) == 0
                        report[f'proxyIPv{family}{proto.upper()}'] = True
            assert dns()!=initial
            report['dnsApplied']=True
            if fixture.startswith('upstream'):
                for family, endpoint in [(4,'https://1.1.1.1/cdn-cgi/trace'),(6,'https://[2606:4700:4700::1111]/cdn-cgi/trace')]:
                    r=host('curl','-q','--noproxy','*','-'+str(family),'-fsS','--max-time','12',endpoint,check=False)
                    ips=[v[3:] for v in r.stdout.decode().splitlines() if v.startswith('ip=')]
                    report['egress'+str(family)] = str(ipaddress.ip_address(ips[0])) if ips else None
                r=host('getent','ahostsv4','example.com',check=False,timeout=18)
                report['dnsLookup']=r.returncode==0
            else:
                for x,addr in [('4','10.79.0.1'),('6','fd42:79::1')]:
                    host('ping','-'+x,'-c','1','-W','5',addr)
                    report['wireguardData'+x]=True
            time.sleep(1.2)
            hs=host('wg','show','wgtun0','latest-handshakes').stdout.splitlines()
            report['handshake']=any(int(k.split()[-1])>0 for k in hs)
            assert report['handshake']
            status = host('python3',rpc,'status').stdout.decode()
            assert '秒前' in status and 'Peer' in status
            assert host('python3',rpc,'check').returncode == 0
            print(json.dumps(report),flush=True)
            # Live MTU changes must retain the interface and WireGuard session.
            before=link['ifindex']
            host('python3',rpc,'mtu','1280')
            after=json.loads(host('ip','-j','link','show','dev','wgtun0').stdout)[0]
            assert after['mtu']==1280 and after['ifindex']==before and existing_ssh()
            assert host('python3',rpc,'mtu','1279',check=False).returncode
            assert b'MTU = 1280' in (d/'profile').read_bytes()
            if fixture=='synthetic':
                time.sleep(max(0, started+130-time.monotonic()))
                run('systemctl','is-active','--quiet',unit)
                host('ping','-4','-c','1','-W','5','10.79.0.1')
                host('ping','-6','-c','1','-W','5','fd42:79::1')
                assert existing_ssh()
                report['continuousSeconds']=int(time.monotonic()-started)
            if fixture == 'domain':
                assert 'wg-peer.test:41513 → 10.90.0.2:41513' in status
                hosts.write_text("127.0.0.1 localhost\nfd42:90::2 wg-peer.test\n")
            host('python3',rpc,'restart')
            if fixture == 'domain':
                assert host('wg','show','wgtun0','endpoints').stdout.split()[1] == b'[fd42:90::2]:41513'
                host('ping','-6','-c','1','-W','3','fd42:79::1')
                assert b'Endpoint=wg-peer.test:41513' in (d/'profile').read_bytes()
                report['domainFallbackAndReresolution']=True
            assert json.loads(host('ip','-j','link','show','dev','wgtun0').stdout)[0]['mtu']==1280
            assert existing_ssh()
            host('python3',rpc,'stop')
            assert b'MTU = 1280' in (d/'profile').read_bytes()
            host('python3',rpc,'mtu','default')
            assert b'MTU = 1420' in (d/'profile').read_bytes()
            report['liveMtuAndOfflineReset']=True
            report['manualRestartStop']=True
            assert dns()==initial and existing_ssh()
            for x in ['-4','-6']:
                assert b'1250' not in host('ip',x,'rule').stdout
            assert host('ip','link','show','wgtun0',check=False).returncode!=0
            assert b'wgtun_' not in host('nft','list','tables').stdout
            report['cleanRestore']=True
            if fixture in ('synthetic', 'health'):
                file = d/'profile'
                working = file.read_bytes()
                dead_key = run('wg','pubkey',data=run('wg','genkey').stdout).stdout.strip()
                file.write_bytes(working + b'[Peer]\nPublicKey = ' + dead_key +
                                 b'\nAllowedIPs = 192.0.2.21/32\nEndpoint = 10.90.0.2:41514\n')
                failure = host('python3',rpc,'start',check=False)
                assert failure.returncode and b'10.90.0.2:41514' in failure.stderr
                assert '隧道已停止' in failure.stderr.decode() and b'41513' not in failure.stderr
                assert not (d/'runtime'/'owned.json').exists()
                assert host('ip','link','show','wgtun0',check=False).returncode
                for family in ('-4','-6'):
                    assert b'1250' not in host('ip',family,'rule').stdout
                assert dns()==initial and existing_ssh()
                file.write_bytes(working)
                host('python3',rpc,'start')
                assert not (d/'runtime'/'startup-error').exists()
                assert host('wg','show','wgtun0','persistent-keepalive').stdout.split()[-1] == b'off'
                host('python3',rpc,'stop')
                report['offlinePeerStoppedAndRetrySucceeded']=True
                host('ip','link','add','wgtun0','type','dummy')
                assert run('systemctl','start',unit,check=False).returncode != 0
                assert json.loads(host('ip','-d','-j','link','show','dev','wgtun0').stdout)[0]['linkinfo']['info_kind'] == 'dummy'
                host('ip','link','del','wgtun0')
                run('systemctl','reset-failed',unit)
                report['foreignInterfacePreserved']=True
                # Force an error after the new native link has been created.
                host('ip','link','add','portholder','type','wireguard')
                host('wg','set','portholder','listen-port','41379')
                host('ip','link','set','portholder','up')
                file = d/'profile'
                file.write_bytes(file.read_bytes().replace(b'[Interface]', b'[Interface]\nListenPort=41379'))
                assert run('systemctl','start',unit,check=False).returncode != 0
                assert host('ip','link','show','wgtun0',check=False).returncode != 0
                assert not (d/'runtime'/'owned.json').exists()
                assert existing_ssh() and dns()==initial
                host('ip','link','del','portholder')
                run('systemctl','reset-failed',unit)
                report['partialStartRestored']=True
        except BaseException:
            print(run('journalctl','-u',unit,'-n','12','--no-pager').stdout.decode(),file=sys.stderr)
            raise
    run('systemctl','daemon-reload')

if __name__=='__main__':
    os.umask(0o077)
    root=Path(sys.argv[1])
    result={'fixture':sys.argv[2]}
    try:trial(root,sys.argv[2],result)
    finally:print(json.dumps(result),flush=True)
