#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""华为 HS8145X6

家族：华为 ssmp
默认端口：80
用法：python3 models/hs8145x6.py -H 192.168.1.1
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models._base import run

if __name__ == "__main__":
    sys.exit(run("huawei", 80))
