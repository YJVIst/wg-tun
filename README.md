# WireGuard 原生内核管理菜单

在 Debian 13 的 SSH 终端输入 **`wg`** 即可管理本机的 WireGuard 出口。数据包由 Linux 内核的 `wireguard` 接口处理。管理器随命令启动，服务配置完成即退出。

## 安装与打开

在 Debian 13 的 root 终端运行以下命令。有 sudo 权限的普通用户可先运行 `sudo -i`。

~~~sh
apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wireguard-tools iproute2 python3 util-linux mount
curl -fsSL https://raw.githubusercontent.com/YJVIst/wg-tun/v1.0.0/wg-tun-native.sh -o wg-tun-native.sh && sh ./wg-tun-native.sh
hash -r
wg
~~~

下载命令固定使用 v1.0.0。以后再次打开管理菜单，直接输入 `wg` 即可。

使用项目源码安装时，可在项目目录运行 `sudo sh install.sh`。安装需要运行 systemd 的 Debian 13、具有网络管理权限的 root，以及提供 WireGuard 驱动的内核。安装保留现有配置。当前原生版本可以在服务单元相同且接口归属可验证时在线更新管理器。若使用旧 Rust 版，先运行 `sudo wg-tun stop`，升级后按需开启开机启动。

| 输入 | 用途 |
| --- | --- |
| `wg` | 在交互终端打开中文菜单。普通用户通过 sudo 获取管理权限 |
| `wg show`、`wg genkey` 等 | 执行 Debian 自带的 WireGuard 命令 |
| `wg menu status` | 查看服务、Peer 端点、握手和累计收发流量 |
| `wg menu doctor` | 只读检查主机资源、内核驱动、工具、权限、配置、服务、接口归属与 TCP 22 路由。SSH 路由按本机路由表推算；不会发送探测流量。发现异常时退出码为 1 |
| `wg menu mtu 1380` | 设置隧道 MTU 并保存，运行中立即生效。输入 `wg menu mtu default` 恢复 1420 |
| `wg menu --help` | 显示所有管理子命令 |
| `wg-tun` | 兼容已有管理入口 |

菜单入口位于 `/usr/local/bin/wg`，要求该目录在 PATH 中排在 `/usr/bin` 之前。Shell 若缓存了旧路径可执行 `hash -r`。脚本、管道等非交互场景中，无参数 `wg` 保留系统工具的输出和退出码。任何场景都可使用 `/usr/bin/wg` 直接调用原工具。

菜单顶部显示运行时长、负载、内存与磁盘、隧道状态和已保存的连接配置。公网出口通过 curl 分别以 IPv4、IPv6 并行查询 ipify，每次最多等待 3 秒。同一菜单会话最多复用 60 秒，操作隧道或配置后重新查询。出口显示“未能测得”表示该地址族本次查询失败。

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

## MTU 设置

在配置菜单选择「设置隧道 MTU」，可查看当前值、输入新值或按回车取消。含 IPv6 地址的配置可设为 1280–9000，纯 IPv4 可设为 576–9000。运行时直接修改现有接口，停止时仅更新保存的配置。

## 网络行为

- `AllowedIPs` 控制本机哪些目标经隧道出站。支持 IPv4、IPv6、双栈、多个 Peer 和按前缀分流。没有对应隧道路由的目标继续使用系统路由。
- 管理器在专用表 52970 中安装路由，主路由表保留。TCP 源端口或目的端口为 22 的连接走原网络，涵盖服务器对 SSH 入站连接的回复，以及本机发起的 SSH 连接。其他端口的入站业务回包也可能受全隧道路由影响。
- WireGuard 的外层 UDP 使用路由标记。已解析端点的 UDP 流量走原网络。遇到同名接口、地址冲突、专用表占用或相关地址族已有自定义策略路由时，启动会报告冲突。接口清理按创建时记录的归属执行。
- 配置 DNS 时，按当前系统使用 systemd-resolved、resolvconf 或临时绑定挂载。停止后恢复。省略 DNS 时沿用主机设置。
- 可导入字段包括 Address、PrivateKey、ListenPort、MTU、DNS、PublicKey、PresharedKey、AllowedIPs、Endpoint、PersistentKeepalive。DNS 接受 IP 地址。上游可使用域名、IPv4 或带方括号的 IPv6 端点。配置中的脚本钩子会被拒绝。
- 本工具管理本机的三层出站隧道。转发其他设备的流量、NAT 或提供应用层代理需要单独配置。
