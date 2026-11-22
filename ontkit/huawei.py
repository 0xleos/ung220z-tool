# -*- coding: utf-8 -*-
"""华为系（ssmp 框架）：Web 登录、开启 Telnet、shell 登录。

适用：HS8145X6、B866-L1 等华为 ONT。

⚠ 状态：实验性。华为各版本固件差异大，以下流程基于公开资料整理，
   未在真机验证。工具会把每一步的原始响应打印出来，便于按实际情况调整。

已知事实（公开资料）：
  * 电信版默认超管 telecomadmin / nE7jA%5m
  * 移动版默认超管 CMCCAdmin / aDm8H%MdA
  * Telnet 默认 root / adminHW，进入后常需 su 提权
  * 部分固件需要在 Web「安全 → 设备访问控制」里显式开启 Telnet
"""
import base64
import hashlib
import re

from .core import Http, Telnet, log

MAX_ATTEMPTS = 3   # 多数设备连续错 3 次就会锁账号，必须克制

DEFAULT_ACCOUNTS = [
    ("telecomadmin", "nE7jA%5m"),
    ("CMCCAdmin", "aDm8H%MdA"),
    ("telecomadmin", "admintelecom"),
    ("root", "admin"),
]

# 已知的 Telnet 开启入口（逐个尝试，命中即停）
TELNET_ENDPOINTS = [
    "/onttelnet.cgi",
    "/enableTelnet.cgi",
    "/cgi-bin/telnetenable.cgi?telnetenable=1",
    "/html/ssmp/telnet/telnet.asp",
]


class HuaweiWeb:
    def __init__(self, host, port=80, timeout=8):
        self.base = "http://%s" % host if port in (80, None) else "http://%s:%d" % (host, port)
        self.host, self.port = host, port
        self.http = Http(self.base, timeout)
        self.attempts = 0

    def fingerprint(self):
        html, st = self.http.get("/")
        marks = {
            "ssmp": "ssmp" in html.lower(),
            "华为": "huawei" in html.lower() or "华为" in html,
            "登录页": "login" in html.lower() or "密码" in html,
        }
        log("PROBE", "GET / → %d，特征 %s" % (st, marks))
        return html

    def login(self, user, pw, schemes=None):
        """尝试华为常见登录方式，返回是否成功。

        schemes 为 None 时依次尝试 plain/b64/sha256；传入列表可限制尝试次数。
        """
        page, _ = self.http.get("/")
        token = ""
        m = re.search(r'name="Frm_Logintoken"[^>]*value="([^"]*)"', page)
        if m:
            token = m.group(1)

        if schemes is None:
            schemes = [
                ("plain", pw),
                ("b64", base64.b64encode(pw.encode()).decode()),
                ("sha256-b64", base64.b64encode(hashlib.sha256(pw.encode()).digest()).decode()),
                ("sha256-hex", hashlib.sha256(pw.encode()).hexdigest()),
            ]
        for name, value in schemes:
            if self.attempts >= MAX_ATTEMPTS:
                log("WARN", "已尝试 %d 次，停止以免触发账号锁定" % self.attempts)
                return False
            self.attempts += 1
            data = {
                "UserName": user,
                "PassWord": value,
                "Language": "chinese",
                "Frm_Logintoken": token,
            }
            try:
                body, st = self.http.post_form("/login.cgi", data)
            except Exception as e:
                log("DEBUG", "login.cgi 异常: %s" % e)
                continue
            ok = st == 200 and ("用户名或密码" not in body) and ("error" not in body.lower()[:200])
            log("AUTH", "%s/%s [%s] → %d %s" % (user, pw, name, st, "可能成功" if ok else "失败"))
            if ok and self._logged_in():
                return True
        return False

    def _logged_in(self):
        try:
            body, _ = self.http.get("/html/ssmp/common/status.asp")
            return "login" not in body.lower()[:400]
        except Exception:
            return False

    def try_default_accounts(self):
        """每个默认账号只试 1 次（明文），把 3 次机会留给 3 个账号。

        若确认账号正确但编码方式不对，请用 -u/-P 显式指定，会走完整编码尝试。
        """
        log("INFO", "尝试默认账号，每账号 1 次（共 %d 次，超出会锁账号）" % MAX_ATTEMPTS)
        for u, p in DEFAULT_ACCOUNTS:
            if self.attempts >= MAX_ATTEMPTS:
                break
            if self.login(u, p, schemes=[("plain", p)]):
                log("DATA", "登录成功：%s / %s" % (u, p))
                return u, p
        log("WARN", "默认账号均失败；如确认账号，请用 -u/-P 指定以尝试编码变体")
        return None

    def enable_telnet(self):
        for ep in TELNET_ENDPOINTS:
            try:
                body, st = self.http.get(ep)
            except Exception as e:
                log("DEBUG", "%s → 异常 %s" % (ep, e))
                continue
            hit = st == 200 and len(body) < 2000
            log("HTTP", "%s → %d %s" % (ep, st, ("（可能已开启）" if hit else "")))
            if hit and ("success" in body.lower() or "成功" in body):
                return True
        log("WARN", "自动开启 Telnet 未成功：华为各版本入口差异大，"
                    "请在 Web 界面「安全 → 设备访问控制」手动开启")
        return False


def telnet_shell(host, user="root", passwords=("adminHW", "admin", "root"), port=23):
    t = Telnet(host, port)
    for pw in passwords:
        if t.login(user, [pw]):
            log("AUTH", "Telnet %s/%s 登录成功" % (user, pw))
            return t
    t.close()
    return None


SU_HINT = """
华为 ONT 进入 shell 后通常还需要 su 提权：

    login: root
    password: adminHW
    > su
    password: <由设备序列号推算，各固件算法不同>

序列号可从 Web「状态 → 设备信息」或设备背面标签读取。
本工具不内置该推算算法（各版本差异大且无可靠公开实现），
拿到 SN 后可在社区按型号查找对应的 shell 密码计算方式。
"""
