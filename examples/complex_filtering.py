#!/usr/bib/env python
"""
Filter requests by having full access to the mitmproxy request object.

Only filtered requests can be tampered via tamper_request and tamper_response or diffed.

URL_FILTER_REGEX or filter_request() can be used for filtering. Absence of both will
allow all requests, which is not a good idea generally

"""

from mitmpeep import HTTPSPeeper, Modes


class ComplexFilteringPeep(HTTPSPeeper):
    def filter_request(self, request):
        # Do any complex filtering here and return True/False
        return(request.method == "POST" and request.urlencoded_form and "message" in list(request.urlencoded_form.keys()))

def start():
    return(ComplexFilteringPeep(mode=Modes.TAMPER))
