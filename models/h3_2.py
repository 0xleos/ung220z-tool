#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""吉比特 H3-2

家族：ZTE 系（九联/吉比特均基于中兴方案）
默认端口：80
用法：python3 models/h3_2.py -H 192.168.1.1 -u user -P '背面贴纸密码' --extract
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run

if __name__ == "__main__":
    sys.exit(run("zte", 80))
