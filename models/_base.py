# -*- coding: utf-8 -*-
"""型号入口的公共启动逻辑：补默认端口后转交 ontkit。"""
import sys

from ontkit.cli import main


def run(family, default_port, argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "-p" not in argv and "--port" not in argv:
        argv = ["-p", str(default_port)] + argv
    return main([family] + argv)
