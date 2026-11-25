#!/usr/bin/python3
"""Debian wg-tun controller. Native Linux WireGuard, managed on demand."""
import base64
import fcntl
import getpass
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ETC = Path("/etc/wg-tun")
PROFILE = ETC / "tunnel.conf"
RUN = Path("/run/wg-tun")
STATE = RUN / "owned.json"
DEV = "wgtun0"
UNIT = "wg-tun.service"
TABLE = "52970"
MARK = "0xcb6a"
PROTO = "237"
BASE = 12500

class Problem(Exception):
    pass

class UpstreamProblem(Problem):
    pass

def call(*args, data=None, check=True, quiet=False, timeout=30):
    r = subprocess.run(list(map(str, args)), input=data, capture_output=True, timeout=timeout)
    if check and r.returncode:
        detail = "" if quiet else r.stderr.decode(errors="replace").strip()
        raise Problem(f"{args[0]} {args[1]} 失败 {detail}".strip())
    return r

def atomic(path, raw):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        temp = Path(f.name)
        try:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
            os.replace(temp, path)
        finally:
            temp.unlink(missing_ok=True)

def validate_key(s):
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        raise Problem("WireGuard 密钥的 Base64 编码无效") from None
    if len(raw) != 32 or not any(raw):
        raise Problem("WireGuard 密钥必须是有效的 32 字节值")

def number(s, low, high):
    if not re.fullmatch(r"[0-9]{1,5}", s) or not low <= int(s) <= high:
        raise Problem("端口、MTU 或保活时间超出范围")
    return int(s)

def config(raw):
    if len(raw) > 128 * 1024:
        raise Problem("配置超过 128 KiB")
    text = raw.decode("utf-8-sig")
    sections = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.partition("#")[0].strip()
        if not line:
            continue
        if line in ("[Interface]", "[Peer]"):
            sections.append((line, {}))
            continue
        if not sections or "=" not in line:
            raise Problem(f"第 {lineno} 行格式错误")
        k, v = map(str.strip, line.split("=", 1))
        kind, fields = sections[-1]
        allowed = ({"Address", "PrivateKey", "ListenPort", "MTU", "DNS"} if kind == "[Interface]"
                   else {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"})
        if k not in allowed:
            raise Problem(f"第 {lineno} 行包含不支持的指令（仅接受标准隧道参数）")
        if k in fields and k in {"Address", "AllowedIPs", "DNS"}:
            fields[k] += "," + v
        elif k in fields or not v:
            raise Problem(f"第 {lineno} 行字段重复或为空")
        else:
            fields[k] = v
    if [kind for kind, _ in sections].count("[Interface]") != 1 or not sections or sections[0][0] != "[Interface]" or len(sections) < 2:
        raise Problem("需要一个 [Interface] 和至少一个 [Peer]")
    iface = sections[0][1]
    def items(value):
        return [s.strip() for s in value.split(",")]
    validate_key(iface.get("PrivateKey", ""))
    addresses = [ipaddress.ip_interface(s) for s in items(iface.get("Address", ""))]
    if any(a.ip.is_unspecified or a.ip.is_multicast or a.ip.is_loopback or a.ip.is_link_local for a in addresses):
        raise Problem("无效的隧道地址")
    families = {a.version for a in addresses}
    mtu = number(iface.get("MTU", "1420"), 1280 if 6 in families else 576, 9000)
    dns = [str(ipaddress.ip_address(s)) for s in items(iface["DNS"])] if "DNS" in iface else []
    lines = ["[Interface]", "PrivateKey = " + iface["PrivateKey"], "FwMark = " + MARK]
    if "ListenPort" in iface:
        lines.append("ListenPort = " + str(number(iface["ListenPort"], 0, 65535)))
    routes, peers = set(), set()
    for _, peer in sections[1:]:
        key = peer.get("PublicKey", "")
        validate_key(key)
        if key in peers:
            raise Problem("Peer 公钥重复")
        peers.add(key)
        if "PresharedKey" in peer:
            validate_key(peer["PresharedKey"])
        if "PersistentKeepalive" in peer:
            number(peer["PersistentKeepalive"], 0, 65535)
        endpoint = peer.get("Endpoint", "")
        match = re.fullmatch(r"(?:\[([a-fA-F0-9:]+)\]|([a-zA-Z0-9._-]+)):([0-9]+)", endpoint)
        if not match:
            raise Problem("出口模式需要每个 Peer 都有 Endpoint（主机:端口，IPv6 使用方括号）")
        if match[1]:
            ipaddress.IPv6Address(match[1])
        number(match[3], 1, 65535)
        for item in items(peer.get("AllowedIPs", "")):
            route = ipaddress.ip_network(item, strict=True)
            if route.version not in families or route in routes:
                raise Problem("AllowedIPs 缺少同族 Address 或与其他条目重复")
            routes.add(route)
        lines += ["[Peer]"] + [f"{k} = {v}" for k, v in peer.items()]
    return addresses, sorted(routes, key=lambda n: (n.version, int(n.network_address), n.prefixlen)), mtu, dns, ("\n".join(lines) + "\n").encode()

def profile():
    st = PROFILE.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise Problem("配置须为 root 所有的 0600 普通文件")
    return PROFILE.read_bytes()

def ip(family, *args, **kwargs):
    return call("ip", "-" + str(family), *args, **kwargs)

def rules(family, endpoints=()):
    # The nop target resumes the host's original routing policy for SSH and outer UDP.
    end = str(BASE + 9)
    entries = [
        (9, ["nop"]),
        (0, ["ipproto", "tcp", "sport", "22", "goto", end]),
        (1, ["ipproto", "tcp", "dport", "22", "goto", end]),
        (2, ["fwmark", MARK, "goto", end]),
        # Strict reverse-path filtering checks incoming encrypted UDP against
        # the route back to the peer, without the outbound socket mark.
        *((2, ["to", str(addr), "ipproto", "udp", "goto", end])
          for addr in endpoints if addr.version == family),
        (3, ["iif", "lo", "lookup", TABLE]),
    ]
    return [["pref", str(BASE + offset), *body, "protocol", PROTO] for offset, body in entries]

def dns_method():
    resolver = Path("/etc/resolv.conf")
    if resolver.is_symlink():
        if shutil.which("resolvectl") and call("resolvectl", "status", check=False).returncode == 0:
            return "resolved"
        if shutil.which("resolvconf") and "resolvconf" in str(resolver.resolve()):
            return "resolvconf"
        raise Problem("当前 DNS 由外部程序管理，无法安全应用 DNS；可移除配置中的 DNS 以沿用系统设置")
    if not resolver.is_file() or call("findmnt", "-M", resolver, check=False).returncode == 0:
        raise Problem("/etc/resolv.conf 非普通文件或已有挂载，无法安全临时挂载 DNS")
    return "bind"

def apply_dns(dns, state):
    method = dns_method()
    data = "".join("nameserver " + addr + "\n" for addr in dns).encode()
    state["dns"] = method
    owned(state)
    if method == "resolved":
        call("resolvectl", "dns", DEV, *dns)
        call("resolvectl", "domain", DEV, "~.")
    elif method == "resolvconf":
        call("resolvconf", "-a", DEV + ".wg-tun", data=data)
    else:
        overlay = RUN / "resolv.conf"
        atomic(overlay, data)
        overlay.chmod(0o644)
        call("mount", "--bind", overlay, "/etc/resolv.conf")

def restore_dns(state):
    method = state.get("dns")
    if method == "resolvconf":
        call("resolvconf", "-d", DEV + ".wg-tun")
    elif method == "bind":
        overlay = RUN / "resolv.conf"
        if overlay.exists() and os.path.samefile(overlay, "/etc/resolv.conf"):
            call("umount", "/etc/resolv.conf")
    # systemd-resolved discards per-link settings when the link disappears.

def link_info(name):
    links = json.loads(call("ip", "-d", "-j", "link", "show").stdout)
    return next((link for link in links if link["ifname"] == name), {})

def owned_link(state):
    link = link_info(DEV)
    return (bool(state.get("alias")) and link.get("ifalias") == state["alias"]
            and link.get("linkinfo", {}).get("info_kind") == "wireguard")

def prepare(raw):
    addresses, routes, _, dns, _ = config(raw)
    if STATE.exists() or link_info(DEV):
        raise Problem("接口 wgtun0 或上次运行记录已存在，请检查服务日志")
    assigned = {item["local"] for link in json.loads(call("ip", "-j", "addr").stdout)
                for item in link["addr_info"]}
    if any(str(a.ip) in assigned for a in addresses):
        raise Problem("隧道地址与本机现有地址冲突")
    for fam in sorted({r.version for r in routes}):
        current = json.loads(ip(fam, "-j", "rule", "show").stdout)
        defaults = {(0, "local"), (32766, "main"), (32767, "default")}
        if any((r["priority"], r.get("table")) not in defaults for r in current):
            raise Problem(f"IPv{fam} 已有自定义策略路由。请先核对 SSH 路径，自动启动已中止")
        existing = json.loads(ip(fam, "-N", "-j", "route", "show", "table", "all").stdout)
        if any(str(r.get("table")) == TABLE for r in existing):
            raise Problem("专用路由表已占用")
    if dns:
        dns_method()
    RUN.mkdir(mode=0o700, exist_ok=True)
    temp = "wgt" + secrets.token_hex(6)
    if link_info(temp):
        raise Problem("临时接口名已占用，请重试")
    state = {"rules": [], "temporary": temp, "alias": "wg-tun-" + secrets.token_hex(16)}
    owned(state)
    return state

def owned(state):
    atomic(STATE, json.dumps(state).encode())

def peer_fields(field):
    rows = call("wg", "show", DEV, field).stdout.decode().splitlines()
    return dict(row.split(maxsplit=1) for row in rows)

def verify_upstreams(expected, timeout=15):
    endpoints = peer_fields("endpoints")
    if set(endpoints) != set(expected):
        absent = ", ".join(expected[k] for k in expected.keys() - endpoints.keys())
        raise UpstreamProblem(f"上游未能加载到 WireGuard 接口，请核对 Peer 公钥和端点 {absent}")
    original = peer_fields("persistent-keepalive")
    # This is a newly created interface. A nonzero timestamp can only belong
    # to this activation, even if the wall clock moved during the check.
    def keepalive(values):
        args = []
        for key, value in values.items():
            args.extend(("peer", key, "persistent-keepalive", value))
        if args:
            call("wg", "set", DEV, *args)
    changed = {key: value for key, value in original.items() if value != "1"}
    keepalive(dict.fromkeys(changed, "1"))
    until = time.monotonic() + timeout
    while True:
        times = peer_fields("latest-handshakes")
        pending = [key for key in expected if int(times.get(key, "0")) == 0]
        if not pending:
            keepalive(changed)
            return
        if time.monotonic() >= until:
            names = ", ".join(expected[key] for key in pending)
            raise UpstreamProblem(f"上游 {names} 在 {timeout} 秒内未完成 WireGuard 握手")
        time.sleep(0.5)

def configure():
    raw = profile()
    state = prepare(raw)
    addresses, routes, mtu, dns, wire = config(raw)
    call("ip", "link", "add", "dev", state["temporary"], "type", "wireguard")
    call("ip", "link", "set", "dev", state["temporary"], "name", DEV, "alias", state["alias"])
    if not owned_link(state):
        raise Problem("无法验证原生接口的类型与归属")
    expected = {}
    for section in wire.decode().split("[Peer]")[1:]:
        fields = dict(line.split(" = ", 1) for line in section.strip().splitlines())
        expected[fields["PublicKey"]] = fields["Endpoint"]
    os.environ["WG_ENDPOINT_RESOLUTION_RETRIES"] = "0"
    try:
        call("wg", "setconf", DEV, "/dev/stdin", data=wire, quiet=True)
    except (Problem, subprocess.TimeoutExpired):
        raise UpstreamProblem("无法应用 WireGuard 配置，请核对端点解析和节点参数：" + ", ".join(expected.values())) from None
    actual_mark = call("wg", "show", DEV, "fwmark").stdout.strip()
    if int(actual_mark, 0) != int(MARK, 0):
        raise Problem("WireGuard 外层报文标记未生效")
    call("ip", "link", "set", "dev", DEV, "mtu", mtu, "up")
    verify_upstreams(expected)
    for a in addresses:
        ip(a.version, "address", "add", str(a), "dev", DEV, "noprefixroute",
           *(["nodad"] if a.version == 6 else []))
    for route in routes:
        ip(route.version, "route", "add", str(route), "dev", DEV, "table", TABLE)
    peers = call("wg", "show", DEV, "endpoints").stdout.decode().splitlines()
    endpoints = {ipaddress.ip_address(line.split()[1].rsplit(":", 1)[0].strip("[]")) for line in peers}
    for fam in sorted({r.version for r in routes}):
        for spec in rules(fam, endpoints):
            state["rules"].append([fam, spec])
            owned(state)
            ip(fam, "rule", "add", *spec)
    if dns:
        apply_dns(dns, state)
    print("原生 WireGuard 已就绪，TCP 22 使用原路由。", flush=True)

def cleanup():
    if not STATE.exists():
        return
    state = json.loads(STATE.read_bytes())
    if "temporary" not in state or "alias" not in state:
        raise Problem("旧版运行记录需要由旧服务清理")
    for fam, spec in reversed(state["rules"]):
        r = ip(fam, "rule", "del", *spec, check=False)
        if r.returncode and b"No such file" not in r.stderr and b"No such process" not in r.stderr:
            raise Problem("清理专用规则失败 " + r.stderr.decode().strip())
    restore_dns(state)
    if owned_link(state):
        call("ip", "link", "delete", "dev", DEV)
    temporary = state["temporary"]
    if link_info(temporary).get("linkinfo", {}).get("info_kind") == "wireguard":
        call("ip", "link", "delete", "dev", temporary)
    (RUN / "resolv.conf").unlink(missing_ok=True)
    STATE.unlink()

def active():
    return call("systemctl", "show", "--property=ActiveState", "--value", UNIT).stdout.strip().decode()

def styled(text, code):
    if sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ:
        return f"\033[{code}m{text}\033[0m"
    return text

def volume(size):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024

def status():
    phase = active()
    enabled = call("systemctl", "is-enabled", UNIT, check=False).stdout.decode().strip()
    phases = {"active": "运行中", "inactive": "已停止", "failed": "启动或清理失败"}
    print(styled("WireGuard  /  本机出口", "1;36"))
    print(f"  服务      {phases.get(phase, phase)}    开机启动  {enabled}")
    if not PROFILE.exists():
        print("  配置      等待导入，可使用 wg menu import <路径>")
        return
    raw = profile()
    addr, routes, mtu, dns, _ = config(raw)
    print("  地址     ", ", ".join(map(str, addr)), "   MTU", mtu)
    print("  路由     ", ", ".join(map(str, routes)))
    print("  DNS      ", ", ".join(dns) if dns else "跟随系统")
    if phase != "active":
        return
    state = json.loads(STATE.read_bytes()) if STATE.is_file() else {}
    if not owned_link(state):
        raise Problem("服务与接口状态不一致，请查看日志后重启")
    handshakes, traffic = peer_fields("latest-handshakes"), peer_fields("transfer")
    for key, endpoint in peer_fields("endpoints").items():
        stamp = int(handshakes[key])
        age = f"{max(0, int(time.time())-stamp)} 秒前" if stamp else "尚未握手"
        rx, tx = map(int, traffic[key].split())
        print(f"  Peer      {endpoint}   {key[:8]}…")
        print(f"            握手 {age}   ↓ {volume(rx)}   ↑ {volume(tx)}")

def host_resources():
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        name, value = line.split(":", 1)
        if name in ("MemTotal", "MemAvailable"):
            mem[name] = int(value.split()[0]) * 1024
    load = " / ".join(f"{n:.2f}" for n in os.getloadavg())
    return (f"负载 {load}（1/5/15 分钟），可用内存 {volume(mem['MemAvailable'])}"
                              f" / {volume(mem['MemTotal'])}，根分区可用 {volume(shutil.disk_usage('/').free)}")

def system_checks():
    release = platform.freedesktop_os_release()
    supported = release.get("ID") == "debian" and release.get("VERSION_ID") == "13"
    yield "系统", "正常" if supported else "提示", f"{release['PRETTY_NAME']} · Linux {platform.release()}"
    yield "主机资源", "信息", host_resources()
    if Path("/sys/module/wireguard").is_dir():
        yield "内核驱动", "正常", "WireGuard 已就绪"
    elif shutil.which("modinfo") and call("modinfo", "wireguard", check=False).returncode == 0:
        yield "内核驱动", "正常", "WireGuard 模块可用，创建接口时按需加载"
    else:
        yield "内核驱动", "提示", "未从 sysfs 或模块索引确认 WireGuard 支持，请核对运行内核配置"
    required = ("ip", "wg", "python3", "systemctl", "mount", "umount", "findmnt", "journalctl")
    missing = [name for name in required if not shutil.which(name)]
    yield "管理工具", "异常" if missing else "正常", "缺少 " + ", ".join(missing) if missing else "依赖齐全"
    if not shutil.which("curl"):
        yield "公网出口查询", "提示", "安装 curl 后可显示双栈公网出口"
    cap = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", Path("/proc/self/status").read_text(), re.M)
    net_admin = cap and int(cap[1], 16) & (1 << 12)
    yield "网络权限", "正常" if net_admin else "异常", "具备 CAP_NET_ADMIN" if net_admin else "当前环境缺少 CAP_NET_ADMIN"

    if PROFILE.exists():
        try:
            addresses, routes, _, _, wire = config(profile())
            yield "隧道配置", "正常", f"{len(addresses)} 个地址，{len(routes)} 个路由前缀，{wire.count(b'[Peer]')} 个 Peer"
        except (ValueError, OSError, Problem):
            yield "隧道配置", "异常", "无法读取或校验配置，请使用 wg menu check 检查"
    else:
        yield "隧道配置", "提示", "尚未导入配置"

    phase = None
    if "systemctl" not in missing:
        unit = call("systemctl", "show", UNIT, "-p", "LoadState", "-p", "ActiveState", "-p", "UnitFileState", check=False)
        props = dict(row.split("=", 1) for row in unit.stdout.decode().splitlines() if "=" in row)
        phase = props.get("ActiveState")
        good = unit.returncode == 0 and props.get("LoadState") == "loaded" and phase != "failed"
        yield "隧道服务", "正常" if good else "异常", (
            f"{props.get('LoadState', '无法读取')} / {phase or '未知'}，开机启动 {props.get('UnitFileState', '未知')}")
    if "ip" in missing:
        return
    if phase == "active":
        try:
            managed = owned_link(json.loads(STATE.read_bytes()))
        except (OSError, ValueError, AttributeError, Problem):
            managed = False
        yield "接口归属", "正常" if managed else "异常", f"{DEV} 与运行记录" + ("一致" if managed else "不一致")
    elif phase == "inactive" and (STATE.exists() or link_info(DEV)):
        yield "接口归属", "提示", f"服务已停止，仍存在 {DEV} 或运行记录，请检查归属"

    connection = os.environ.get("SSH_CONNECTION", "").split()
    client = None
    if connection:
        try:
            client = ipaddress.ip_address(connection[0])
        except ValueError:
            pass
    for family, reference in ((4, "192.0.2.1"), (6, "2001:db8::1")):
        target = str(client) if client and client.version == family else reference
        devices = []
        for sport, dport in (("22", "45000"), ("45000", "22")):
            result = ip(family, "-j", "route", "get", target, "ipproto", "tcp", "sport", sport, "dport", dport, check=False)
            rows = json.loads(result.stdout) if result.returncode == 0 else []
            devices.append(rows[0].get("dev") if rows else None)
        level = "异常" if DEV in devices else ("提示" if None in devices else "正常")
        yield f"IPv{family} SSH 22", level, f"目标 {target}，回包 {devices[0] or '无路由'}，出站 {devices[1] or '无路由'}"

def doctor():
    print(styled("WireGuard  /  系统状态检查", "1;36"))
    errors = 0
    colors = {"正常": "32", "异常": "31", "提示": "33", "信息": "36"}
    for label, level, detail in system_checks():
        print(f"  {styled(level, colors[level])}  {label}   {detail}")
        errors += level == "异常"
    if errors:
        raise Problem(f"系统检查发现 {errors} 项异常")

@contextmanager
def profile_lock():
    RUN.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(RUN, os.O_DIRECTORY | os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)

def save_profile(raw):
    config(raw)
    with profile_lock():
        if active() not in ("inactive", "failed"):
            raise Problem("请先停止隧道，再修改配置")
        atomic(PROFILE, raw)
    print("配置已验证并保存。")

def with_mtu(raw, value):
    addresses, _, _, _, _ = config(raw)
    minimum = 1280 if any(a.version == 6 for a in addresses) else 576
    if not re.fullmatch(r"[0-9]{1,4}", value) or not minimum <= int(value) <= 9000:
        raise Problem(f"此配置允许的 MTU 范围为 {minimum}–9000")
    encoded = str(int(value)).encode()
    # Edit only the value so comments, CRLF, keys and peers survive unchanged.
    updated, count = re.subn(rb"(?m)^([ \t]*MTU[ \t]*=[ \t]*)[0-9]+",
                             lambda m: m[1] + encoded, raw, count=1)
    if not count:
        header = re.search(rb"(?m)^(?:\xef\xbb\xbf)?[ \t]*\[Interface\][^\r\n]*(\r?\n)", raw)
        if not header:
            raise Problem("无法定位 Interface 配置段")
        updated = raw[:header.end()] + b"MTU = " + encoded + header[1] + raw[header.end():]
    config(updated)
    return updated

def change_mtu(args):
    if not PROFILE.is_file():
        raise Problem("请先导入或创建隧道配置")
    if len(args) > 1:
        raise Problem("用法：wg menu mtu [数值|default]")
    if args:
        value = args[0]
    else:
        addresses, _, current, _, _ = config(profile())
        minimum = 1280 if any(a.version == 6 for a in addresses) else 576
        print(f"当前配置 MTU {current}，允许范围 {minimum}–9000，默认值 1420。")
        if not sys.stdin.isatty():
            return
        value = input("输入新 MTU 或 default，回车取消 › ").strip()
        if not value:
            return
    with profile_lock():
        raw = profile()
        updated = with_mtu(raw, "1420" if value == "default" else value)
        mtu = config(updated)[2]
        phase = active()
        if phase not in ("active", "inactive", "failed"):
            raise Problem("服务正在切换状态，请稍后重试")
        if phase == "active":
            if not STATE.exists() or not owned_link(json.loads(STATE.read_bytes())):
                raise Problem("无法验证运行接口归属，请检查系统状态")
            previous = link_info(DEV)["mtu"]
            call("ip", "link", "set", "dev", DEV, "mtu", mtu)
            try:
                if updated != raw:
                    atomic(PROFILE, updated)
            except OSError:
                call("ip", "link", "set", "dev", DEV, "mtu", previous)
                raise
        elif updated != raw:
            atomic(PROFILE, updated)
    when = "已在运行接口生效" if phase == "active" else "下次启动生效"
    print(f"隧道 MTU 已保存为 {mtu}，{when}。")

def create_profile():
    addresses = input("本机隧道地址与前缀，多地址用逗号分隔 > ").strip()
    families = {ipaddress.ip_interface(x.strip()).version for x in addresses.split(",")}
    allowed = ",".join(n for fam,n in ((4,"0.0.0.0/0"),(6,"::/0")) if fam in families)
    endpoint = input("上游 Endpoint（主机:端口） > ").strip()
    peer = input("上游公钥 > ").strip()
    private = getpass.getpass("本机私钥（留空生成新密钥） > ").strip()
    if not private:
        private = call("wg", "genkey").stdout.decode().strip()
    psk = getpass.getpass("预共享密钥（可留空） > ").strip()
    dns = input("隧道 DNS（留空沿用系统设置） > ").strip()
    nets = input(f"AllowedIPs（留空采用 {allowed}） > ").strip() or allowed
    values = ["[Interface]", "Address = "+addresses, "PrivateKey = "+private]
    if dns:
        values.append("DNS = "+dns)
    values.extend(["[Peer]", "PublicKey = "+peer, "Endpoint = "+endpoint, "AllowedIPs = "+nets])
    if psk:
        values.append("PresharedKey = "+psk)
    save_profile(("\n".join(values)+"\n").encode())
    print("请在上游登记本机公钥", call("wg","pubkey",data=(private+"\n").encode(),quiet=True).stdout.decode().strip())

def dispatch(cmd, args):
    if cmd == "configure":
        failure = RUN / "startup-error"
        failure.unlink(missing_ok=True)
        try:
            with profile_lock():
                configure()
        except UpstreamProblem as exc:
            atomic(failure, str(exc).encode())
            raise
    elif cmd == "cleanup":
        with profile_lock():
            cleanup()
    elif cmd == "import":
        if active() not in ("inactive", "failed"):
            raise Problem("请先停止隧道，再导入新配置")
        src = Path(args[0] if args else input("配置文件路径 > ").strip())
        with src.open("rb") as f:
            raw = f.read(128 * 1024 + 1)
        save_profile(raw)
    elif cmd == "create":
        create_profile()
    elif cmd in ("start", "restart"):
        config(profile())
        if cmd == "start" and active() == "active":
            print("隧道已在运行。")
            return
        print("正在启动隧道并检查上游握手…", flush=True)
        result = call("systemctl", cmd, UNIT, check=False, timeout=100)
        if result.returncode:
            failure = RUN / "startup-error"
            if failure.is_file():
                clean = "隧道已停止。" if not STATE.exists() else "请检查服务清理日志。"
                raise Problem(f"{failure.read_text()}。{clean}")
            raise Problem("启动失败，请运行 wg menu logs 查看服务日志")
        print("上游握手成功，隧道已启动。")
    elif cmd == "stop":
        call("systemctl", "stop", UNIT)
        print("隧道已停止。")
    elif cmd == "enable":
        config(profile())
        call("systemctl", "enable", UNIT)
        print("已启用开机启动。")
    elif cmd == "disable":
        call("systemctl", "disable", UNIT)
        print("已关闭开机启动。")
    elif cmd == "check":
        if args:
            with Path(args[0]).open("rb") as f:
                raw = f.read(128 * 1024 + 1)
        else:
            raw = profile()
        addresses, routes, mtu, dns, wire = config(raw)
        print(f"配置有效   地址 {len(addresses)}   Peer {wire.count(b'[Peer]')}   前缀 {len(routes)}   MTU {mtu}   DNS {len(dns)}")
    elif cmd == "mtu":
        change_mtu(args)
    elif cmd == "doctor":
        doctor()
    elif cmd == "status":
        status()
    elif cmd == "logs":
        subprocess.run(["journalctl", "--no-pager", "-u", UNIT, "-n", "45"], check=True)
    elif cmd == "routes":
        for fam, probe in [(4, "192.0.2.1"), (6, "2001:db8::1")]:
            for args in [[], ["ipproto", "tcp", "sport", "22", "dport", "45000"], ["ipproto", "tcp", "sport", "45000", "dport", "22"], ["mark", MARK]]:
                r = ip(fam, "route", "get", probe, *args, check=False)
                print("IPv" + str(fam), " ".join(args) or "普通流量", (r.stdout or r.stderr).decode().strip())
    else:
        raise Problem("未知命令")

MENU = (
    ("连接", (("status", "查看状态、握手与流量"), ("start", "启动隧道"),
              ("stop", "停止并恢复网络"), ("restart", "重启隧道"))),
    ("配置", (("import", "从文件导入配置"), ("create", "交互创建配置"), ("check", "校验当前配置"),
              ("mtu", "设置隧道 MTU"))),
    ("运维", (("enable", "开启开机启动"), ("disable", "关闭开机启动"),
              ("routes", "诊断双栈与 SSH 路由"), ("logs", "查看近期日志"), ("doctor", "检查系统状态"))),
)

def public_ip(family):
    if not shutil.which("curl"):
        return "缺少 curl"
    try:
        result = call("curl", "-q", f"-{family}", "--noproxy", "*", "--fail", "--silent",
                      "--max-time", "3", "--max-filesize", "128", "https://api64.ipify.org", check=False)
        if result.returncode == 0:
            address = ipaddress.ip_address(result.stdout.decode("ascii").strip())
            if address.version == family and address.is_global:
                return str(address)
    except (ValueError, OSError, subprocess.SubprocessError):
        pass
    return "未能测得"

def menu_overview():
    elapsed = int(float(Path("/proc/uptime").read_text().split()[0]))
    days, seconds = divmod(elapsed, 86400)
    os_name = platform.freedesktop_os_release()["PRETTY_NAME"]
    print(f"  主机      {platform.node()} · {os_name} · 已运行 {days} 天 {seconds//3600} 小时")
    print("  资源     ", host_resources())
    phase = active()
    labels = {"active": "运行中", "inactive": "已停止", "failed": "失败"}
    print(f"  隧道      {labels.get(phase, phase)} · {DEV}")
    failure = RUN / "startup-error"
    if phase == "failed" and failure.is_file():
        print("  启动失败 ", failure.read_text())
    if not PROFILE.exists():
        print("  连接配置  尚未导入")
        return
    try:
        addresses, routes, mtu, dns, wire = config(profile())
    except (ValueError, OSError, Problem):
        print("  连接配置  无法读取或校验，请使用 wg menu check")
        return
    endpoints = [row.removeprefix("Endpoint = ") for row in wire.decode().splitlines() if row.startswith("Endpoint = ")]
    defaults = {net.version for net in routes if net.prefixlen == 0}
    mode = ["IPv" + str(fam) + (" 全隧道" if fam in defaults else " 分流") for fam in sorted({net.version for net in routes})]
    print(f"  连接配置  {PROFILE.name} · {', '.join(mode)} · MTU {mtu}")
    print("  上游端点 ", ", ".join(endpoints))
    print("  隧道地址 ", ", ".join(map(str, addresses)))
    print("  DNS      ", ", ".join(dns) if dns else "跟随系统")

def menu():
    actions = [cmd for _, items in MENU for cmd, _ in items]
    refresh_at = 0
    while True:
        print("\n" + styled("━━  WireGuard  /  原生内核管理  ━━", "1;36"))
        try:
            menu_overview()
        except (ValueError, OSError, Problem, subprocess.SubprocessError):
            print("  部分系统状态暂不可用，请使用 wg menu doctor")
        if time.monotonic() >= refresh_at:
            with ThreadPoolExecutor(max_workers=2) as pool:
                ipv4, ipv6 = pool.map(public_ip, (4, 6))
            refresh_at = time.monotonic() + 60
        print(f"  公网 IPv4 {ipv4}\n  公网 IPv6 {ipv6}\n")
        number = 0
        for group, items in MENU:
            print(styled("  " + group, "1;34"))
            for _, label in items:
                number += 1
                print(f"    {number:>2}   {label}")
        choice = input("     0   退出\n选择 › ").strip()
        if choice == "0":
            return
        if choice not in {str(n) for n in range(1, len(actions)+1)}:
            print("请输入菜单中的编号。")
            continue
        try:
            action = actions[int(choice)-1]
            if action in ("start", "restart", "stop", "import", "create"):
                refresh_at = 0
            dispatch(action, [])
        except (ValueError, OSError, Problem, subprocess.SubprocessError) as e:
            print(styled("操作失败  ", "31") + str(e), file=sys.stderr)

def main():
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    os.environ["LC_ALL"] = "C"
    os.umask(0o077)
    if sys.argv[1:] in (["-h"], ["--help"], ["help"]):
        print("wg 打开菜单    wg menu <命令>    wg-tun [命令]")
        for _, items in MENU:
            for cmd, label in items:
                print(f"  {cmd:9} {label}")
        print("wg menu import <文件>    wg menu check [文件]    wg menu mtu [数值|default]")
        return
    if os.geteuid():
        raise Problem("请使用 root 或 sudo 运行")
    if len(sys.argv) > 1:
        dispatch(sys.argv[1], sys.argv[2:])
        return
    menu()

if __name__ == "__main__":
    try:
        main()
    except (Problem, OSError, ValueError, subprocess.SubprocessError) as e:
        sys.exit(str(e))
    except (KeyboardInterrupt, EOFError):
        sys.exit(1)
