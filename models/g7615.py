#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""中兴 ZXHN G7615

家族：ZTE 系（webFac 工厂模式已验证可开 Telnet）
默认端口：8080
用法：python3 models/g7615.py -H 192.168.1.1 --mode factory --enable-telnet
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run

if __name__ == "__main__":
    sys.exit(run("zte", 8080))
