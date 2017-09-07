#!/usr/bib/env python
"""
The idea behind this example is to ease the process of testing privilege
escalations or typically incorrect authorization. The manual way to test
this is to repeat requests in burp and manually add a different account session's
token. With the following script not only that functionality can be automated
but you get a pretty logging as well as diff files that should give a clearer picture.

"""

from mitmpeep import HTTPSPeeper, Modes


class PrivilegeEscalationPeep(HTTPSPeeper):
    MODE = Modes.DIFFER
    URL_FILTER_REGEX = "endpoint\?"  # A regex to filter interesting requests

    def tamper_request(self, request):
        # Identifier eases the identification part, see the output below
        request.mpeep_identifier = "Current User"
        return(request)

    # The way you test for horizontal escalation is you try the same request with
    # a different account but similar role cookie
    def tamper_for_replay(self, request):
        cookies = request.cookies
        cookies["fancy_session"] = "a_valid_session_of_other_user"
        request.mpeep_identifier = "Diff User"
        request.cookies = cookies
        return(request)

"""
This script will log
    + diff to the log file
    + the diff to a file $output_dir/<any_host>/super/oracle/<unique_hash>.diff.0

"""
