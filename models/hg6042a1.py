#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""烽火 HG6042A1（移动定制）

家族：烽火 FiberHome
默认端口：8080（Telnet 开关也在 8080）
用法：python3 models/hg6042a1.py -H 192.168.1.1 -m AA:BB:CC:DD:EE:FF

流程（据公开实操）：
  1. /cgi-bin/telnetenable.cgi?telnetenable=1&key=<MAC 大写>
  2. telnet admin / Fh@<MAC 后六位大写>
  3. load_cli factory → show admin_name / show admin_pwd
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run

if __name__ == "__main__":
    sys.exit(run("fiberhome", 8080))
