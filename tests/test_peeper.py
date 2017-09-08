import os
import types
import shutil
import unittest

from unittest.mock import MagicMock

from mitmproxy.test import tflow, taddons
from mitmpeep import HTTPSPeeper, Modes


def get_flow():
    f = tflow.tflow(resp=True)
    f.request.url = 'http://www.google.com/robots.txt'
    f.request.headers['User-Agent'] = "Not a real one!"
    del f.request.headers['header']  # Added by mitmproxy??
    f.request.method = "POST"
    f.request.content = b"BOTS"

    f.response.status_code = 200
    f.response.reason = "OK"
    f.response.headers['Set-Cookie'] = "Really!?"
    f.response.content = b"NO BOTS"
    return(f)

def get_replayed_flow():
    f = get_flow()
    f2 = get_flow()
    f.mpeep_old_request = f2.request
    f.mpeep_old_response = f2.response
    f.request.is_replay = True
    f.request.headers['User-Agent'] = "Anything non existent"
    f.response.headers['Set-Cookie'] = "Yes, Rreally!"
    return(f)



class TamperRequest(HTTPSPeeper):
    def tamper_request(self, request):
        request.headers["User-Agent"] = "User-Agent"
        return(request)

    def tamper_response(self, response):
        response.content = b"YES BOTS"
        return(response)


class TestHTTPSPeeper(unittest.TestCase):

    def test_request_tamper(self):
        hw = TamperRequest()
        f = get_flow()

        hw.request(f)
        self.assertEqual(f.request.headers["User-Agent"], "User-Agent")

    def test_filter_request(self):
        hw = HTTPSPeeper()
        hw.URL_FILTER_REGEX = ".*robots.txt$"
        hw.tamper_request = MagicMock()
        f = get_flow()

        hw.request(f)
        self.assertTrue(hw.tamper_request.called)

    def test_tamper_calls(self):
        hw = HTTPSPeeper()
        f = get_flow()
        hw.tamper_request = MagicMock(return_value=f.request)
        hw.tamper_response = MagicMock(return_value=f.response)

        hw.request(f)
        self.assertTrue(hw.tamper_request.called)

        hw.response(f)
        self.assertTrue(hw.tamper_response.called)

    def test_escape_quotes(self):
        hw = HTTPSPeeper()
        self.assertIn("\'", hw._escape_quotes("'", q="'"))

    def test_curlify(self):
        hw = HTTPSPeeper()
        f = get_flow()

        curl = hw.curlify(f.request)
        expected = ("curl -X POST -d 'BOTS' -H 'content-length: 4'" +
                    " -H 'User-Agent: Not a real one!' 'http://www.google.com/robots.txt'")
        self.assertEqual(curl, expected)

    def test_stringify(self):
        hw = HTTPSPeeper()
        f = get_flow()

        self.assertTrue(isinstance(hw.stringify_request(f.request), str))
        self.assertTrue(isinstance(hw.stringify_response(f.response), str))

    def test_diff(self):
        hw = HTTPSPeeper()
        f = get_flow()

        self.assertTrue(isinstance(hw.diff_request(f.request, f.request), types.GeneratorType))
        self.assertTrue(isinstance(hw.diff_response(f.response, f.response), types.GeneratorType))

    def test_simple(self):
        if os.path.exists(HTTPSPeeper.OUTPUT_DIR):
            shutil.rmtree(HTTPSPeeper.OUTPUT_DIR)

        hw = HTTPSPeeper()
        # If output dir exists, delete and try
        f = get_flow()

        hw.request(f)
        hw.response(f)

    def test_differ_mode_replayed_request(self):
        hw = HTTPSPeeper()
        hw.MODE = Modes.DIFFER
        hw.URL_FILTER_REGEX = None
        with taddons.context() as tctx:
            self.assertIsNotNone(tctx)
            f = get_replayed_flow()

            hw.request(f)
            hw.response(f)

    def test_differ_mode_request(self):
        hw = HTTPSPeeper()
        hw.MODE = Modes.DIFFER
        hw.URL_FILTER_REGEX = None
        with taddons.context() as tctx:
            tctx.master.view = MagicMock()
            tctx.master.replay_request = MagicMock()
            f = get_replayed_flow()
            f.request.is_replay = False

            hw.request(f)
            hw.response(f)

            self.assertTrue(tctx.master.view.add.called)
            self.assertTrue(tctx.master.replay_request.called)

    def test_beautify_json(self):
        hw = HTTPSPeeper()
        hw.beautify_json("{1:1}")
        hw.beautify_json("{")
        hw.beautify_json({1:1})
        hw.beautify_json([1,1])

    def test_set_identifier(self):
        hw = HTTPSPeeper()
        f = get_flow()

        hw.set_identifier(f.request, "anything")
        self.assertEqual(getattr(f.request, hw.IDENTIFIER_NAME, ""), "anything")

if __name__ == "__main__":
    unittest.main()
