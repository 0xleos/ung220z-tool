# -*- coding: utf-8 -*-
"""中兴系 Web（.gch 框架）：登录、枚举页面、解密配置、提取凭据。

适用：ZXHN G7615、九联 UNG220Z / UNG853H、吉比特 H3-2，以及登录页为
getAES() 的 H10g-ax（中国移动）。UNG220Z 的登录口令只做 base64；
H10g-ax 是 AES-128-CBC + PKCS7（key ``1111111111111111``，iv ``0000000000000000``），
且 ``Frm_Logintoken`` 固定为 2。该机型没有 telnet.gch / webFac，Telnet 由
``tele_sec_tserver_t.gch`` 打开，且只开 LAN。
注意：不同厂商默认端口不同（中兴工厂模式 8080，九联/吉比特/H10g-ax 多为 80）。
"""
import base64
import html as html_mod
import re

from .core import Http, Telnet, log

CFG_ENC = "/userconfig/cfg/db_user_cfg.xml"
CFG_DEC = "/tmp/debug-decry-cfg"
# 登录页 getAES()：AES-128-CBC + PKCS7，密文再 base64。与 CryptoJS 把 key/iv 当 WordArray 的结果一致。
AES_KEY = b"1111111111111111"
AES_IV = b"0000000000000000"
TSERVER_PATH = "/getpage.gch?pid=1002&nextpage=tele_sec_tserver_t.gch"


def _unescape(v):
    """还原 JS 的 \\xNN 转义与 HTML 实体。"""
    v = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)
    return html_mod.unescape(v)


def page_title(html):
    m = re.search(r"<title>([^<]*)</title>", html or "", re.I)
    return m.group(1).strip() if m else ""


def uses_aes_login(html):
    """H10g-ax / getAES 登录页。其它 .gch 页（含 UNG220Z）仍只做 base64。"""
    if not html:
        return False
    if "h10g" in page_title(html).lower():
        return True
    low = html.lower()
    return "getaes(" in low or AES_KEY.decode("ascii") in html


def _parsed_token(html):
    m = re.search(r'Frm_Logintoken"\)\.value\s*=\s*"(\d+)"', html or "")
    if m:
        return m.group(1)
    m = re.search(r'name\s*=\s*"Frm_Logintoken"[^>]*value\s*=\s*"(\d+)"', html or "", re.I)
    if m:
        return m.group(1)
    return None


def login_token(html):
    """H10g-ax 固定填 2。其它页面回填脚本里的值；getAES 页缺省 2，base64 页缺省 7。"""
    if "h10g" in page_title(html).lower():
        return "2"
    parsed = _parsed_token(html)
    if parsed is not None:
        return parsed
    return "2" if uses_aes_login(html) else "7"


def _aes_backend():
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:
        raise RuntimeError("AES 登录需要 cryptography 包（ontkit 工厂模式已使用它）") from e
    return padding, Cipher, algorithms, modes


def aes_cbc_b64(text, key=AES_KEY, iv=AES_IV):
    """AES-128-CBC + PKCS7，再 base64。key/iv 为 ASCII 字节，不是口令派生。"""
    padding, Cipher, algorithms, modes = _aes_backend()
    padder = padding.PKCS7(128).padder()
    data = padder.update(text.encode("utf-8")) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(ct).decode("ascii")


def aes_cbc_unb64(blob, key=AES_KEY, iv=AES_IV):
    padding, Cipher, algorithms, modes = _aes_backend()
    raw = base64.b64decode(blob)
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    data = dec.update(raw) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode("utf-8")


def encode_password(password, html):
    if uses_aes_login(html):
        return aes_cbc_b64(password)
    return base64.b64encode(password.encode("utf-8")).decode("ascii")


def login_form(user, password, html):
    return {
        "username": user,
        "logincode": encode_password(password, html),
        "textpwd": "",
        "frashnum": "",
        "ieversion": "1",
        "Frm_Logintoken": login_token(html),
        "action": "login",
    }


def _looks_like_aes_b64(value):
    s = (value or "").strip()
    if len(s) < 24 or len(s) % 4:
        return False
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return False
    return len(raw) >= 16 and len(raw) % 16 == 0


def _password_text(s):
    return bool(s) and all(ord(c) >= 32 and ord(c) != 127 for c in s)


def decrypt_ts_password(value):
    """TS_UPwd 在 H10g-ax 上是同一套 AES 密文；解不开就原样返回（UNG220Z 为明文）。"""
    if not _looks_like_aes_b64(value):
        return value
    try:
        plain = aes_cbc_unb64(value.strip())
    except Exception:
        return value
    return plain if _password_text(plain) else value


def transfer_values(html):
    out = {}
    for k, v in re.findall(r"Transfer_meaning\('([A-Za-z_0-9]+)','((?:[^'\\]|\\.)*)'\)", html or ""):
        if v and not k.startswith("IF_"):
            out[k] = _unescape(v)
    return out


def js_assign(html, name):
    m = re.search(r"\b%s\s*=\s*(['\"])((?:\\.|(?!\1).)*)\1" % re.escape(name), html or "")
    return _unescape(m.group(2)) if m else ""


def input_value(html, name):
    name_re = re.escape(name)
    patterns = [
        r'name\s*=\s*"%s"[^>]*value\s*=\s*"([^"]*)"' % name_re,
        r"name\s*=\s*'%s'[^>]*value\s*=\s*'([^']*)'" % name_re,
        r'value\s*=\s*"([^"]*)"[^>]*name\s*=\s*"%s"' % name_re,
        r"value\s*=\s*'([^']*)'[^>]*name\s*=\s*'%s'" % name_re,
    ]
    for p in patterns:
        m = re.search(p, html or "", re.I)
        if m:
            return _unescape(m.group(1))
    return ""


def session_token(html):
    if not html:
        return ""
    m = re.search(r"var\s+session_token\s*=\s*(['\"])(.*?)\1", html)
    if not m:
        m = re.search(r"\bsession_token\s*=\s*(['\"])(.*?)\1", html)
    if m:
        return _unescape(m.group(2))
    for p in (
        r'name\s*=\s*"_SESSION_TOKEN"[^>]*value\s*=\s*"([^"]*)"',
        r"name\s*=\s*'_SESSION_TOKEN'[^>]*value\s*=\s*'([^']*)'",
        r'value\s*=\s*"([^"]*)"[^>]*name\s*=\s*"_SESSION_TOKEN"',
        r"value\s*=\s*'([^']*)'[^>]*name\s*=\s*'_SESSION_TOKEN'",
    ):
        m = re.search(p, html, re.I)
        if m and m.group(1):
            return _unescape(m.group(1))
    return ""


def tserver_fields(html):
    vals = transfer_values(html)
    uname = vals.get("TS_UName") or js_assign(html, "TS_UName") or input_value(html, "TS_UName")
    enc = vals.get("TS_UPwd") or js_assign(html, "TS_UPwd") or input_value(html, "TS_UPwd")
    return uname, enc, session_token(html)


def telnet_enable_fields(uname, upwd_enc, token):
    """提交页面上的密文口令，只打开 LAN。"""
    return {
        "TS_Enable": "1",
        "Lan_Enable": "1",
        "Wan_Enable": "0",
        "TS_UName": uname,
        "TS_UPwd": upwd_enc,
        "IF_ACTION": "apply",
        "_SESSION_TOKEN": token,
    }


class ZteWeb:
    def __init__(self, host, port=80, user="user", password="", timeout=8):
        self.base = "http://%s" % host if port in (80, None) else "http://%s:%d" % (host, port)
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.http = Http(self.base, timeout)
        self.login_html = ""

    def login(self):
        html, _ = self.http.get("/")
        self.login_html = html
        try:
            fields = login_form(self.user, self.password, html)
        except RuntimeError as e:
            log("WARN", str(e))
            return False
        body, _ = self.http.post_form("/", fields)
        if 'name="logincode"' not in body and len(body) > 5000:
            log("AUTH", "%s 登录成功（%s）" % (self.user, self.base))
            return True
        if "其他用户" in body:
            log("WARN", "设备提示「其他用户正在配置」，先释放会话再试")
        elif len(re.findall(r'errmsg"\)\.innerHTML = "([^"]*)"', body)) > 1:
            log("WARN", "登录次数超限，设备处于延时校验")
        else:
            log("WARN", "登录失败：账号或密码错误")
        return False

    def page(self, name):
        body, _ = self.http.get("/getpage.gch?pid=1002&nextpage=" + name)
        return "" if "页面超时" in body else body

    def enable_telnet(self):
        """POST tele_sec_tserver_t.gch，打开 LAN Telnet。返回 (用户名, 明文口令)。"""
        body, _ = self.http.get(TSERVER_PATH)
        if not body or "页面超时" in body:
            log("WARN", "读不到 Telnet 配置页 tele_sec_tserver_t.gch")
            return None
        uname, enc, token = tserver_fields(body)
        if not uname or not enc:
            log("WARN", "Telnet 配置页没有 TS_UName/TS_UPwd")
            return None
        if not token:
            log("WARN", "页面没有 session_token，仍提交开启请求")
        self.http.post_form(TSERVER_PATH, telnet_enable_fields(uname, enc, token))
        plain = decrypt_ts_password(enc)
        log("HTTP", "tele_sec_tserver_t.gch → 已请求开启 LAN Telnet（%s）" % uname)
        return uname, plain

    def pages(self):
        tmpl = self.page("template.gch")
        return sorted(set(re.findall(r"nextpage=([A-Za-z0-9_.]+\.gch)", tmpl)))

    @staticmethod
    def values(html):
        """解析 Transfer_meaning 键值；设备常把 @ 写成 \\x40，需还原。"""
        return transfer_values(html)

    @staticmethod
    def rows(html):
        out = []
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S):
            cells = [_unescape(re.sub(r"<[^>]+>", "", c)).strip()
                     for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)]
            cells = [c for c in cells if c]
            if len(cells) >= 2:
                out.append(cells)
        return out


# ───────────────────── 通过 Telnet 读配置 ─────────────────────
def decrypt_config(tn):
    tn.run("sidbg 1 DB decry %s" % CFG_ENC)
    if not tn.run("ls %s" % CFG_DEC).strip():
        log("WARN", "配置解密失败（%s 不存在）" % CFG_DEC)
        return False
    log("SHELL", "sidbg 1 DB decry → %s" % CFG_DEC)
    return True


def table(tn, name):
    out = tn.run("sed -n '/<Tbl name=\"%s\"/,/<\\/Tbl>/p' %s" % (name, CFG_DEC))
    rows = []
    for blk in re.findall(r'<Row No="\d+">(.*?)</Row>', out, re.S):
        rows.append(dict(re.findall(r'<DM name="([A-Za-z_0-9]+)" val="([^"]*)"', blk)))
    return rows


def extract_credentials(tn):
    """返回 dict：web / telnet / pppoe / wifi / root。"""
    creds = {"web": [], "telnet": [], "pppoe": [], "wifi": []}
    for r in table(tn, "DevAuthInfo"):
        if r.get("User"):
            creds["web"].append((r["User"], r.get("Pass", ""), r.get("Level", "")))
            log("DATA", "Web 账号 %-12s %s  Level=%s" % (r["User"], r.get("Pass"), r.get("Level")))
    for r in table(tn, "TelnetUser"):
        if r.get("Username"):
            creds["telnet"].append((r["Username"], r.get("Password", "")))
            log("DATA", "Telnet   %-12s %s" % (r.get("Username"), r.get("Password")))
    for r in table(tn, "WANCPPP"):
        if r.get("UserName"):
            creds["pppoe"].append((r["UserName"], r.get("Password", "")))
            log("DATA", "PPPoE    %-12s %s" % (r["UserName"], r.get("Password")))
    for r in table(tn, "WLANPSK"):
        if r.get("KeyPassphrase"):
            creds["wifi"].append((r.get("ViewName", ""), r["KeyPassphrase"]))
            log("DATA", "WiFi     %-24s %s" % (r.get("ViewName"), r["KeyPassphrase"]))
    shadow = tn.run("grep root /etc/shadow | head -1")
    m = re.search(r"root:(\$[0-9]\$[^:]+):", shadow)
    if m:
        creds["root"] = m.group(1)
        log("DATA", "root 哈希 %s" % m.group(1)[:40])
    return creds
