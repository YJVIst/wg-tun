#!/bin/sh
set -eu
cd "$(dirname "$0")"
test "$(id -u)" = 0 || { echo '请以 root 或 sudo 安装'; exit 1; }
. /etc/os-release
test "$ID/$VERSION_ID" = debian/13 || { echo '本安装器适用于 Debian 13'; exit 1; }
test -x /usr/bin/wg || { echo "请先安装 wireguard-tools"; exit 1; }
for tool in ip python3 systemctl mount umount findmnt journalctl; do
    command -v "$tool" >/dev/null || { echo "缺少 $tool。请运行 apt-get install --no-install-recommends iproute2 wireguard-tools python3 util-linux mount systemd"; exit 1; }
done
lib=/usr/local/lib/wg-tun
bin=/usr/local/bin/wg-tun
units=/etc/systemd/system
case "$(systemctl show -p ActiveState --value wg-tun.service)" in
    active)
        # The native oneshot keeps its state in the kernel. A manager-only
        # upgrade is safe when its unit and cleanup state are compatible.
        if ! cmp -s systemd/wg-tun.service "$units/wg-tun.service" ||
           test "$(systemctl show -p SubState --value wg-tun.service)" != exited ||
           ! python3 -I - <<'PY_STATE'
import json
import subprocess
from pathlib import Path
state = json.loads(Path("/run/wg-tun/owned.json").read_bytes())
link, = json.loads(subprocess.check_output(["ip", "-d", "-j", "link", "show", "wgtun0"]))
assert state["alias"] and link.get("ifalias") == state["alias"]
assert link["linkinfo"]["info_kind"] == "wireguard"
assert {"rules", "temporary"} <= state.keys()
PY_STATE
        then
            echo '当前服务无法在线升级，请先执行 wg-tun stop'; exit 1
        fi ;;
    inactive|failed)
        if test -e /run/wg-tun/owned.json; then
            echo '检测到未清理的运行记录，请先用现有版本恢复网络'; exit 1
        fi ;;
    *) echo '服务正在切换状态，请稍后重试'; exit 1 ;;
esac
check_command() {
    if { test -e "$1" || test -L "$1"; } && test "$(readlink "$1" || true)" != "$2"; then
        echo "已有同名管理命令 $1，请先核对"; exit 1
    fi
}
check_command "$bin" "$lib/manager.py"
check_command /usr/local/bin/wg "$lib/wg"
if test -f "$units/wg-tun.service" && grep -q 'wg-tun-core' "$units/wg-tun.service"; then
    systemctl disable wg-tun.service
fi
# Remove the watchdog installed by earlier releases before replacing its handler.
if test -f "$units/wg-tun-rollback.service"; then
    systemctl stop wg-tun-rollback.service
    rm -f "$units/wg-tun-rollback.service"
fi
rm -f /etc/wg-tun/confirmed.sha256
install -d -m 0755 "$lib" /usr/local/bin
install -d -m 0700 /etc/wg-tun
next_manager=$(mktemp "$lib/.manager.XXXXXXXX")
trap 'rm -f "$next_manager"' EXIT
install -m 0755 manager.py "$next_manager"
install -m 0755 wg "$lib/wg"
ln -sfn "$lib/manager.py" "$bin"
ln -sfn "$lib/wg" /usr/local/bin/wg
install -m 0644 systemd/wg-tun.service "$units/"
systemctl daemon-reload
mv -f "$next_manager" "$lib/manager.py"
echo '原生 WireGuard 管理器已安装。输入 wg 即可打开中文菜单。'
