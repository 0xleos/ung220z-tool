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
