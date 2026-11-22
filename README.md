# ung220z-tool

针对 **UNG220Z（九联 / Unionman 中国移动光猫）** 的一键凭据提取工具。

> ⚠️ 仅用于**你自己的设备**，用于找回自己忘记的管理密码、迁移宽带配置或安全自查。
> 未经授权对他人设备使用属于违法行为，作者不承担任何责任。

## 背景

这类光猫的 Web 管理页基于 `.gch` CGI 框架，登录口令由 TR-069 定期轮换，普通用户拿到的密码往往几天就失效。本工具走 Telnet 通道，直接读取设备配置库，拿到**当下有效**的全部凭据。

## 工作流程

```
用户输入账号密码
   ↓
拼出 http://<ip>/usr=<user>&psw=<pass>&cmd=1&telnet.gch 并打开浏览器（同时脚本直连兜底）
   ↓
Telnet 登录 → root shell
   ↓
sidbg 1 DB decry /userconfig/cfg/db_user_cfg.xml 解密配置
   ↓
提取 Web 账号 / Telnet 口令 / PPPoE / WiFi 密钥 / root 口令
   ↓
打印凭据表 + 落盘日志
```

## 用法

```bash
python3 ung220z.py
```

会依次询问：

```
※ 用户名和密码通常印在光猫【背面贴纸】上（S/N 标签）
  形如「用户名：user   密码：xxxxxxxx」，把光猫翻过来就能看到

① 光猫地址 [192.168.1.1]:
② 用户名 [user]:
③ 密码（输入时不显示）
   密码:
```

也可以全部走命令行：

```bash
python3 ung220z.py -i 192.168.1.1 -u user -p '你的密码'
python3 ung220z.py -i 192.168.1.1 -u user -p '你的密码' --no-browser
```

### 常用参数

| 参数 | 说明 |
|---|---|
| `-i, --ip` | 光猫地址，默认 `192.168.1.1` |
| `-u, --user` | 登录用户名，默认 `user` |
| `-p, --password` | 登录密码，不填则交互输入 |
| `--telnet-user` | Telnet 用户名，默认 `CMCCAdmin` |
| `--telnet-password` | Telnet 口令（部分机型与 Web 口令不同） |
| `--no-browser` | 不调用浏览器，纯 HTTP 请求 |
| `--unlock` | Web 被会话锁占住时重启 httpd 解锁 |
| `--no-release` | 不尝试释放残留 Web 会话 |
| `--telnet-port` | Telnet 端口，默认 23 |
| `--timeout` | 网络超时秒数，默认 8 |

## 输出示例

```
[22:15:00] INFO   会话开始  目标=192.168.1.1  账户=user
[22:15:00] HTTP   已发送给浏览器: http://192.168.1.1/usr=user&psw=***&cmd=1&telnet.gch
[22:15:00] HTTP   telnet.gch → TelnetSet Success!
[22:15:00] PROBE  nc -zv 192.168.1.1 23 → succeeded
[22:15:01] AUTH   Telnet CMCCAdmin / ****** → 登录成功（root）
[22:15:02] SHELL  sidbg 1 DB decry /userconfig/cfg/db_user_cfg.xml → /tmp/debug-decry-cfg
[22:15:03] DATA   DevAuthInfo  CMCCAdmin  / ******  Level=1
[22:15:04] CRACK  MATCH: ******  (/etc/shadow)
```

最后输出凭据汇总表，并写入 `ung220z_<时间戳>.log`。

## 依赖

- Python 3.8+
- 标准库即可，无需 pip 安装
- 设备已开启 Telnet（脚本会自动通过 `telnet.gch` 尝试开启）

## 原理说明

| 环节 | 说明 |
|---|---|
| 开 Telnet | `GET /usr=<user>&psw=<pass>&cmd=1&telnet.gch`，返回 `TelnetSet Success!` 即成功 |
| Web 登录 | 密码前端只做 base64，`Frm_Logintoken` 每次响应递增，必须回填实时值 |
| 配置解密 | `sidbg 1 DB decry` 无口令即可解密，得到明文 XML |
| root 口令 | `/etc/shadow` 中为 SHA-256 crypt，工具会用常见出厂口令比对 |

## 免责声明

本项目仅用于教育与自有设备维护。使用者应确保对目标设备拥有合法管理权限。

## 排障

### `telnet.gch` 返回 404

说明该固件没有这个接口，**不是九联/吉比特的 `.gch` 体系**，本脚本的开启方式不适用。
脚本会打印设备指纹（`Server` 头 + 页面标题）帮助判断。下一步：

```bash
python3 -m ontkit probe -H 192.168.1.1          # 识别固件家族
python3 -m ontkit zte   -H 192.168.1.1 -p 8080  # 中兴系（webFac 工厂模式）
python3 -m ontkit huawei -H 192.168.1.1         # 华为系（ssmp）
```

### `telnet.gch` 成功但 23 端口未监听

- 设备可能在 Web 后台把 Telnet 服务关闭了，只留了开关接口
- 也可能需要几秒才起监听，等一下重试

### Telnet 能连上但登录被拒

Telnet 与 Web 是**两套账号库**。脚本会依次尝试：

1. 你填的 Web 账号（如 `useradmin`）
2. `CMCCAdmin` + 同一口令
3. `--telnet-password` 指定值
4. Web 侧侦察：`manager_aduser_conf_t.gch&IF_INDEX=0` 读管理员行 → 用其口令登录 → `tele_sec_tserver_t.gch` 取 `TS_UPwd`
5. 出厂默认组合

也可以手动在浏览器（已登录状态）打开：

```
http://<光猫IP>/getpage.gch?pid=1002&nextpage=tele_sec_tserver_t.gch
```

页面源码里 `TS_UName` / `TS_UPwd` 就是 Telnet 账号密码。

### 登录失败次数超限

设备通常 3 次失败进入延时校验，**停止重试**，静默等待 10~30 分钟。

## 修复记录

### v1.1（合并社区反馈）

| 问题 | 影响 | 修复 |
|---|---|---|
| `ls` 的 stderr 也落在 pty 上 | 解密失败被判成功，最后打印一张空凭据表 | 改用 `test -s && echo __OK__` 判定 |
| `sed` 区间在单行 XML 上失效 | 所有表混在一起，PPPoE/WiFi 被当成 Web 账号 | 新增 `Cfg` 类，整份 `cat` 一次后本地按 `<Tbl>` 切表（顺带把 6 次往返压成 1 次） |
| Web 页为 GBK 时解码失败 | `其他用户` 匹配不到，`--unlock` 形同虚设 | `_decode` 优先取响应头 charset，再 utf-8→gbk→gb18030 回退 |
| 无 try/finally | 断线时裸 traceback，设备上残留明文配置 | `finally` 中 `rm -f /tmp/debug-decry-cfg`、关闭 Telnet 与日志；日志文件 0600 |
| 口令 `.strip()` | 首尾空格是口令一部分时被改坏 | 改为 `rstrip("\r\n")` |
| URL 明文写日志 | 口令泄漏到日志文件 | 日志中 `psw=***` |
| 固定 marker `__X__` | 配置内容恰好包含该串时输出被截断 | 每次随机 marker |
| `IAC IAC` 未处理 | 吃掉一个 0xFF 字节 | 按 telnet 规范输出字面量 |
| 缺 openssl 时静默 | root 比对无声失败 | 明确提示 |

退出码语义：`0` 成功 / `1` 参数或异常 / `2` 网关不可达 / `3` Telnet 端口未开 / `4` 登录失败 / `5` 配置解密失败 / `130` 用户中断。

## 致谢

- **蓝色大肥鱼** —— 指出并修复了三处会导致「静默假失败」的关键缺陷（解密校验、单行 XML 串表、GBK 解码），并补充了异常清理、口令边界、日志脱敏等改进。原始补丁见 PR #6。
- **[@yitan-xini](https://github.com/yitan-xini)** —— 代为整理与提交上述补丁。

## 机型兼容性

根据 issue 反馈整理，不同固件差异极大，报错前请先对照：

| 型号 | 现象 | 判断 | 下一步 |
|---|---|---|---|
| UNG220Z | 全流程通过 | 中兴 `.gch` | ✅ 目标机型 |
| UNP720Z | `telnet.gch` 成功，Telnet 登录被拒 | Telnet 与 Web 两套账号 | 先用 `useradmin/useradmin`，新版会依次试 8 组 |
| HG6042A1 | `telnet.gch` 400，页面含 `get_factory_mode` | 中兴工厂模式 | `ontkit zte --mode factory` |
| GM232（V1A0.A04.01） | 404 / 400 | 非 `.gch` 或路径不同 | 提供登录页标题与 `Server` 头 |
| SK-D740L | 23 端口未开放 | Telnet 服务未启用 | 先在 Web 后台开启，或确认固件是否支持 |
| 返回 `Mini web server` | 404 | 通用 Web 服务器 | 不是本工具适用机型 |

判断方法：脚本失败时会自动打印 `指纹 Server=... title=... 特征=...`，把这行贴出来即可。
