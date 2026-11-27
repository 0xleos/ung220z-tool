# -*- coding: utf-8 -*-
"""H10g-ax 登录编码、Telnet 开关字段、BusyBox 提示符。不访问网络。"""
import base64
import inspect
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ung220z
from ontkit import core, zte_web

SECRET_B64 = "c2VjcmV0"
SECRET_AES = "GXg3rCJ+/bxis7YTYZbHqQ=="

H10G_PAGE = """<html><title>H10g-ax</title><script>
function dosubmit(){ getAES(pwd); }
document.getElementById("Frm_Logintoken").value = "9";
</script></html>"""

AES_PAGE = """<html><title>ZXHN</title><script>
function getAES(p){ return p; }
document.getElementById("Frm_Logintoken").value = "9";
</script></html>"""

B64_PAGE = """<html><title>UNG220Z</title><script>
document.getElementById("Frm_Logintoken").value = "4";
</script><input name="logincode"></html>"""

TS_PAGE = """<script>
Transfer_meaning('TS_UName','CMCCAdmin');
Transfer_meaning('TS_UPwd','%s');
var session_token = 'tok-1';
</script>""" % SECRET_AES


def first_match(buf, tokens):
    for t in tokens:
        if t in buf:
            return t
    return None


class LoginEncodingTests(unittest.TestCase):
    def test_ung220z_imports_base64(self):
        self.assertEqual(ung220z.base64.b64encode(b"a"), base64.b64encode(b"a"))

    def test_enable_telnet_accepts_timeout(self):
        params = inspect.signature(ung220z.enable_telnet).parameters
        self.assertIn("timeout", params)
        self.assertEqual(params["timeout"].default, 8)
        calls = []
        orig = ung220z.http_get

        def fake_get(url, timeout=8):
            calls.append(timeout)
            return "TelnetSet Success!"

        ung220z.http_get = fake_get
        try:
            ok = ung220z.enable_telnet(
                "127.0.0.1", "user", "pw", open_browser=False, timeout=3.5)
        finally:
            ung220z.http_get = orig
        self.assertTrue(ok)
        self.assertEqual(calls, [3.5])

    def test_h10g_forces_aes_and_token_2(self):
        fields = zte_web.login_form("user", "secret", H10G_PAGE)
        self.assertEqual(fields["Frm_Logintoken"], "2")
        self.assertEqual(fields["logincode"], SECRET_AES)
        self.assertEqual(fields["action"], "login")
        self.assertNotEqual(fields["logincode"], SECRET_B64)

    def test_other_getaes_keeps_parsed_token(self):
        fields = zte_web.login_form("user", "secret", AES_PAGE)
        self.assertEqual(fields["Frm_Logintoken"], "9")
        self.assertEqual(fields["logincode"], SECRET_AES)

    def test_getaes_without_token_defaults_to_2(self):
        html = "<script>function getAES(p){}</script>"
        fields = zte_web.login_form("user", "secret", html)
        self.assertTrue(zte_web.uses_aes_login(html))
        self.assertEqual(fields["Frm_Logintoken"], "2")

    def test_ung_page_stays_base64(self):
        fields = zte_web.login_form("user", "secret", B64_PAGE)
        self.assertFalse(zte_web.uses_aes_login(B64_PAGE))
        self.assertEqual(fields["Frm_Logintoken"], "4")
        self.assertEqual(fields["logincode"], SECRET_B64)

    def test_aes_matches_fixed_vector_and_roundtrip(self):
        self.assertEqual(zte_web.aes_cbc_b64("secret"), SECRET_AES)
        self.assertEqual(zte_web.aes_cbc_unb64(SECRET_AES), "secret")
        for text in ("a", "user", "0123456789abcdef", "aDm8H%MdA"):
            self.assertEqual(zte_web.aes_cbc_unb64(zte_web.aes_cbc_b64(text)), text)

    def test_plaintext_telnet_password_is_not_decrypted(self):
        self.assertEqual(zte_web.decrypt_ts_password("aDm8H%MdA"), "aDm8H%MdA")
        self.assertEqual(zte_web.decrypt_ts_password(SECRET_AES), "secret")


class WebSessionTests(unittest.TestCase):
    def test_websession_posts_h10g_fields(self):
        posted = {}

        class Fake(ung220z.WebSession):
            def __init__(self):
                pass

            def get(self, path, timeout=8):
                return H10G_PAGE

            def post_form(self, path, data, timeout=8):
                posted.update(data)
                return "frame" * 2000

        self.assertTrue(Fake().login("user", "secret"))
        self.assertEqual(posted["logincode"], SECRET_AES)
        self.assertEqual(posted["Frm_Logintoken"], "2")

    def test_websession_posts_base64_for_ung(self):
        posted = {}

        class Fake(ung220z.WebSession):
            def __init__(self):
                pass

            def get(self, path, timeout=8):
                return B64_PAGE

            def post_form(self, path, data, timeout=8):
                posted.update(data)
                return "x" * 6000

        self.assertTrue(Fake().login("user", "secret"))
        self.assertEqual(posted["logincode"], SECRET_B64)
        self.assertEqual(posted["Frm_Logintoken"], "4")


class TelnetPageTests(unittest.TestCase):
    def test_tserver_fields_and_enable_form(self):
        uname, enc, token = zte_web.tserver_fields(TS_PAGE)
        self.assertEqual(uname, "CMCCAdmin")
        self.assertEqual(enc, SECRET_AES)
        self.assertEqual(token, "tok-1")
        self.assertEqual(
            zte_web.session_token("<input name='_SESSION_TOKEN' value='abc'>"), "abc")
        form = zte_web.telnet_enable_fields(uname, enc, token)
        self.assertEqual(form, {
            "TS_Enable": "1",
            "Lan_Enable": "1",
            "Wan_Enable": "0",
            "TS_UName": "CMCCAdmin",
            "TS_UPwd": SECRET_AES,
            "IF_ACTION": "apply",
            "_SESSION_TOKEN": "tok-1",
        })

    def test_enable_telnet_posts_ciphertext(self):
        class FakeHttp:
            def __init__(self):
                self.posts = []

            def get(self, path, raw=False):
                return TS_PAGE, 200

            def post_form(self, path, data):
                self.posts.append((path, data))
                return "ok", 200

        w = zte_web.ZteWeb("192.0.2.1", 80, "user", "secret")
        w.http = FakeHttp()
        cred = w.enable_telnet()
        self.assertEqual(cred, ("CMCCAdmin", "secret"))
        path, data = w.http.posts[0]
        self.assertIn("tele_sec_tserver_t.gch", path)
        self.assertEqual(data["TS_UPwd"], SECRET_AES)
        self.assertEqual(data["Wan_Enable"], "0")
        self.assertEqual(data["Lan_Enable"], "1")


class PromptTests(unittest.TestCase):
    def test_busybox_prompt_without_trailing_space(self):
        self.assertNotIn("$ ", "~ $")
        hit = first_match("~ $", ung220z.TELNET_AFTER_PW)
        self.assertEqual(hit, "~ $")
        self.assertIn(hit, ung220z.TELNET_OK)
        self.assertIn(first_match("~ #", ung220z.TELNET_AFTER_PW), ung220z.TELNET_OK)
        self.assertIn(first_match("/ # ", ung220z.TELNET_AFTER_PW), ung220z.TELNET_OK)
        self.assertIn(first_match("# ", ung220z.TELNET_AFTER_PW), ung220z.TELNET_OK)

    def test_rejection_is_not_a_prompt(self):
        hit = first_match("Login incorrect", ung220z.TELNET_AFTER_PW)
        self.assertEqual(hit, "incorrect")
        self.assertNotIn(hit, ung220z.TELNET_OK)

    def test_prompt_lines_are_stripped_from_command_output(self):
        for line in ("~ $", "~ $ id", "~ #", "/ #", "# ", "$ "):
            self.assertTrue(ung220z.is_shell_prompt_line(line))
            self.assertTrue(core.is_shell_prompt_line(line))
        self.assertFalse(ung220z.is_shell_prompt_line("uid=0(root)"))
        self.assertFalse(core.is_shell_prompt_line("uid=0(root)"))


class ModelEntryTests(unittest.TestCase):
    def test_help_uses_web_mode_defaults(self):
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "models", "h10g_ax.py"), "-h"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--enable-telnet", proc.stdout)
        self.assertIn("tele_sec_tserver", proc.stdout)


if __name__ == "__main__":
    unittest.main()
