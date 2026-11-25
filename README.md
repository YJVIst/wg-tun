# WireGuard 原生内核管理菜单

在 Debian 13 的 SSH 终端输入 **`wg`** 即可管理本机的 WireGuard 出口。数据包由 Linux 内核的 `wireguard` 接口处理。管理器随命令启动，服务配置完成即退出。

## 安装与打开

在 Debian 13 的 root 终端运行以下命令。有 sudo 权限的普通用户可先运行 `sudo -i`。

~~~sh
apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wireguard-tools iproute2 nftables python3 util-linux mount
curl -fsSL https://raw.githubusercontent.com/YJVIst/wg-tun/v1.2.1/wg-tun-native.sh -o wg-tun-native.sh && sh ./wg-tun-native.sh
hash -r
wg
~~~

下载命令固定使用 v1.2.1。以后再次打开管理菜单，直接输入 `wg` 即可。

使用项目源码安装时，可在项目目录运行 `sudo sh install.sh`。安装需要运行 systemd 的 Debian 13、具有网络管理权限的 root，以及提供 WireGuard 驱动的内核。安装保留现有配置。当前原生版本可以在服务单元相同且接口归属可验证时在线更新管理器。若使用旧 Rust 版，先运行 `sudo wg-tun stop`，升级后按需开启开机启动。

| 输入 | 用途 |
| --- | --- |
| `wg` | 在交互终端打开中文菜单。普通用户通过 sudo 获取管理权限 |
| `wg show`、`wg genkey` 等 | 执行 Debian 自带的 WireGuard 命令 |
| `wg menu status` | 查看服务、Peer 端点、握手和累计收发流量 |
| `wg menu doctor` | 只读检查主机资源、内核驱动、工具、权限、配置、服务、接口归属与 TCP 22 路由。SSH 路由按本机路由表推算；不会发送探测流量。发现异常时退出码为 1 |
| `wg menu mtu 1380` | 设置隧道 MTU 并保存，运行中立即生效。输入 `wg menu mtu default` 恢复 1420 |
| `wg menu update` | 检查并安装 GitHub 最新稳定版，校验发布包 SHA-256 |
| `wg menu version` | 查看管理脚本版本 |
| `wg menu --help` | 显示所有管理子命令 |
| `wg-tun` | 兼容已有管理入口 |

菜单入口位于 `/usr/local/bin/wg`，要求该目录在 PATH 中排在 `/usr/bin` 之前。Shell 若缓存了旧路径可执行 `hash -r`。脚本、管道等非交互场景中，无参数 `wg` 保留系统工具的输出和退出码。任何场景都可使用 `/usr/bin/wg` 直接调用原工具。

菜单顶部显示运行时长、负载、内存与磁盘、隧道状态和已保存的连接配置。公网出口通过 curl 分别以 IPv4、IPv6 并行查询 ipify，每次最多等待 3 秒。同一菜单会话最多复用 60 秒，操作隧道或配置后重新查询。出口显示“未能测得”表示该地址族本次查询失败。

## 更新管理脚本

输入 `wg`，在「运维」中选择「更新管理脚本」，或运行 `wg menu update`。脚本会比较已安装版本和 GitHub 最新稳定版，下载新版并核对 GitHub 发布资产的 SHA-256。完成后，交互菜单会加载新版。配置及开机启动设置沿用本机原值。如果新版变更了正在运行的服务单元，安装器会提示先停止隧道。

从 v1.2.0 升级时，先用 `command -v nft` 检查依赖。若缺少该命令，运行 `apt-get install -y --no-install-recommends nftables`。执行 `wg menu update` 后，已运行的隧道再执行一次 `wg menu restart` 即可应用代理回程规则。

v1.0.0 和 v1.1.0 首次升级需执行上方「安装与打开」中的下载安装命令，之后即可使用菜单更新。

## 首次接入

1. 在菜单中选择「从文件导入配置」或「交互创建配置」。创建向导可生成本机密钥，并显示用于上游登记的公钥。
2. 选择「启动隧道」。管理器在切换路由和 DNS 前主动检查所有配置节点的 WireGuard 握手，共用 15 秒等待时间。任一节点未响应时，本次启动会停止并提示端点。握手成功后恢复配置中的保活间隔，隧道持续运行，可从状态页查看握手和流量。
3. 检查在启动、重启及开机启动时执行。需要开机自动连接时，执行 `wg menu enable`。

以上操作也可通过 CLI 执行：

~~~sh
wg menu check /path/to/upstream.conf
wg menu import /path/to/upstream.conf
wg menu start
wg menu routes
wg menu status
wg menu enable
~~~

使用 `wg menu stop` 立即恢复网络，`wg menu disable` 关闭开机启动，`wg menu logs` 查看隧道服务日志。更换配置时先停止，再导入。开机启动设置在更换配置后继续生效。配置保存在 root 专用的 `/etc/wg-tun/tunnel.conf`，状态页仅展示公开信息。

## 使用域名节点

在「交互创建配置」的上游端点一栏填写 `vpn.example.com:51820`，也可在导入文件的 `[Peer]` 段填写 `Endpoint = vpn.example.com:51820`。域名可含中文，端口为上游实际监听的 UDP 端口。

启动时通过系统解析器查询域名，支持 IPv4、IPv6 和多地址记录。首选地址未响应时，管理器在原有 15 秒握手窗口内尝试候选地址。运行 `wg menu status` 可查看配置域名和内核当前使用的端点。域名记录变更后，运行 `wg menu restart` 重新解析并连接。

## MTU 设置

在配置菜单选择「设置隧道 MTU」，可查看当前值、输入新值或按回车取消。含 IPv6 地址的配置可设为 1280–9000，纯 IPv4 可设为 576–9000。运行时直接修改现有接口，停止时仅更新保存的配置。

## 网络行为

- `AllowedIPs` 控制本机哪些目标经隧道出站。支持 IPv4、IPv6、双栈、多个 Peer 和按前缀分流。没有对应隧道路由的目标继续使用系统路由。
- 管理器在专用表 52970 中安装路由，主路由表保留。TCP 源端口或目的端口为 22 的连接走原网络，涵盖服务器对 SSH 入站连接的回复，以及本机发起的 SSH 连接。公网客户端连入本机 Xray、sing-box 等代理时，入站 TCP/UDP 连接的回包走系统原路由。代理为客户端新建的出站连接按 AllowedIPs 路由，经隧道发出的包使用隧道地址。端口无需登记，代理可在隧道启动后运行。
- WireGuard 的外层 UDP 使用路由标记。已解析端点的 UDP 流量走原网络。遇到同名接口、地址冲突、专用表占用或相关地址族已有自定义策略路由时，启动会报告冲突。接口清理按创建时记录的归属执行。
- 管理器使用独立的临时 nftables 表，由内核跟踪连接方向，停止隧道时删除该表。已运行的旧隧道在更新管理器后需运行一次 `wg menu restart` 应用新规则。
- 配置 DNS 时，按当前系统使用 systemd-resolved、resolvconf 或临时绑定挂载。停止后恢复。省略 DNS 时沿用主机设置。
- 可导入字段包括 Address、PrivateKey、ListenPort、MTU、DNS、PublicKey、PresharedKey、AllowedIPs、Endpoint、PersistentKeepalive。DNS 接受 IP 地址。上游可使用域名、IPv4 或带方括号的 IPv6 端点。配置中的脚本钩子会被拒绝。
- 本工具管理本机的三层出站隧道。转发其他设备的流量、NAT 或提供应用层代理需要单独配置。
