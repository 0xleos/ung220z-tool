#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中兴 H10g-ax（中国移动）

家族：ZTE 系。.gch 登录页 title 为 H10g-ax，口令用 getAES()
（AES-128-CBC + PKCS7，再 base64），Frm_Logintoken 固定为 2。
默认端口：80。telnet.gch 与 8080 webFac 在该机型上不可用。

用法：python3 models/h10g_ax.py -H 192.168.1.1 -u user -P '贴纸密码' --enable-telnet --extract

流程：Web 登录 → 读 tele_sec_tserver_t.gch 的 TS_UName / TS_UPwd
→ POST 打开 LAN Telnet（Wan_Enable=0）→ sidbg 解密配置。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--mode" not in argv:
        argv = ["--mode", "web"] + argv
    return run("zte", 80, argv)


if __name__ == "__main__":
    sys.exit(main())
