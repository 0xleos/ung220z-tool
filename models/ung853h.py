#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""九联 UNG853H（中国移动定制）

家族：ZTE 系（.gch 框架 + lastgood.xml/sidbg 配置）
默认端口：80
用法：python3 models/ung853h.py -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run

if __name__ == "__main__":
    sys.exit(run("zte", 80))
