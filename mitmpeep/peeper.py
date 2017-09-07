#!/usr/bin/env python
import os
import re
import sys
import json
import urllib
import difflib
import hashlib
import logging
import tempfile
import itertools

from mitmproxy import ctx
from mitmproxy.net.http.request import Request
from mitmproxy.net.http.response import Response


class Modes:
    TAMPER = 0
    DIFFER = 1


logger = logging.getLogger(__name__)
sys.dont_write_bytecode = True


class HTTPSPeeper(object):

    """Extensible object to ease the development of
    writing mitmproxy scripts
    """
    # If None, all the requests are logged
    URL_FILTER_REGEX = None

    # Logging configuration
    OUTPUT_DIR = "output"
    LOG_FILE = "mitmpeeper.log"
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = "%(message)s"
    LOG_DIFFS = True
    LOG_FLOWS = True

    # Save diffs, curls and requests to files
    WRITE_TO_FILES = True

    # Don't edit
    IDENTIFIER_NAME = "mpeep_identifier"

    @property
    def MODE(self):
        """Property method for MODE

        Returns:
            int: Integer specifying Mode

        """
        return(self._MODE)

    @MODE.setter
    def MODE(self, value):
        """Property setter for MODE

        Args:
            value (int): Mode to set to

        Returns:
            None

        """
        if value == Modes.TAMPER:
            self._MODE = value
            self.LOG_FLOWS = True
        elif value == Modes.DIFFER:
            self._MODE = value
            self.LOG_FLOWS = False

    def __init__(self, mode=Modes.TAMPER):
        """Initialize the object.
        """
        self.__init_logging()
        self.MODE = mode

    def __init_logging(self):
        """Initialize logging to a file.

        Returns:
            None

        """
        if not os.path.exists(self.OUTPUT_DIR):
            os.mkdir(self.OUTPUT_DIR)
        logging.basicConfig(
                filename=os.path.join(self.OUTPUT_DIR, self.LOG_FILE),
                filemode="a",
                format=self.LOG_FORMAT,
                datefmt="%H:%M",
                level=self.LOG_LEVEL
        )
        self.logger = logger

    @staticmethod
    def _escape_quotes(string, q="'"):
        """Escape quotes so that string can be used inside the quote
        for a shell command. Useful in safely constructing command strings.

        curl -H 'X-Custom-Header: Adam's Apple' ->
        curl -H 'X-Custom-Header: Adam\'s Apple'

        Args:
            string (str): String which needs escaping.

        Kwargs:
            q (str): Character that needs to be escaped (i.e ',").

        Returns:
            str: Escaped string.

        """
        return(string.replace(q, "\\{}".format(q)))

    def filter_request(self, request):
        """Checks if the request matches the given regex.
        This method can be overridden to implement custom filtering logic.

        Args:
            request (Request): Request object.

        Returns:
            bool: tamper functions are called on the request if True.

        """
        return((self.URL_FILTER_REGEX is not None and
                re.search(self.URL_FILTER_REGEX, request.url, re.IGNORECASE)) or
               self.URL_FILTER_REGEX is None)

    def request(self, flow):
        """Called by mitmproxy on request.

        Args:
            flow (Flow): Mitmproxy Flow.

        Returns: None.

        """
        # First check modes
        if self.MODE == Modes.TAMPER or self.MODE == Modes.DIFFER:
            # If there is a tamper function and the request meets the filter
            # Only tamper mode can tamper request here and make sure it is not a replayed request
            if self.filter_request(flow.request) and not flow.request.is_replay:
                flow.request = self.tamper_request(flow.request)

    def response(self, flow):
        """Called by mitmproxy on response.

        Args:
            flow (Flow): Mitmproxy flow.

        Returns: None.

        """
        if self.filter_request(flow.request):
            # Calculate path only for the main request, all modified requests
            # will append _mod to the path
            flow.mpeep_file_storage_path = getattr(flow, "_file_storage_path", None) or self.get_unique_path(flow.request)

            if self.MODE == Modes.TAMPER:
                    flow.response = self.tamper_response(flow.response)

            # Save after tampering is done, so just in case user beautified
            # JSON, we save the good looking one as user wants it
            self.store_transaction(flow.mpeep_file_storage_path, flow.request, flow.response)

            if self.MODE == Modes.DIFFER:
                # If this is an original request and not a replay
                if not flow.request.is_replay:
                    # Create new flow, add old req-res to the new flow and replay
                    self.tnr_request(flow)
                else:
                    self.store_diff(
                        flow.mpeep_file_storage_path,
                        flow.mpeep_old_request,
                        flow.request,
                        flow.mpeep_old_response,
                        flow.response
                    )


    def tnr_request(self, flow):
        """Tamper n Replay the request.

        Args:
            flow (Flow): Current mitmproxy flow.

        Returns:
            Flow: A new tampered copy of old flow.

        """
        new_flow = flow.copy()
        new_flow.mpeep_old_request = flow.request
        new_flow.mpeep_old_response = flow.response
        new_flow.mpeep_file_storage_path = flow.mpeep_file_storage_path + "_tampered"
        ctx.master.view.add(new_flow)
        new_flow.request = self.tamper_for_replay(new_flow.request)
        ctx.master.replay_request(new_flow)

    def log_diff(self, old_req, new_req, old_res, new_res):
        """Log the diff to logger and return the diff lines
        to be written as diff files. Can be overridden if
        you want to show the diff in a different format than the
        standard one.

        Args:
            old_req (Request): Original Request.
            new_req (Request): Tampered Request.
            old_res (Response): Original Response.
            new_res (Response): Tampered Response.

        Returns:
            generator: Yields diff lines for requests.
            generator: Yields diff lines for responses.

        """
        request_diff_lines = self.diff_request(old_req, new_req)
        response_diff_lines = self.diff_response(old_res, new_res)

        filtered_request_lines = list(filter(lambda x: re.match("[\+-\?]", x), request_diff_lines))
        filtered_response_lines = list(filter(lambda x: re.match("[\+-\?]", x), response_diff_lines))

        if self.LOG_DIFFS is True:
            if len(filtered_request_lines) > 0:
                logger.info("{title:-^120}\n\n{lines}\n".format(
                    title=" Request Diff ",
                    lines="\n".join(filtered_request_lines)))
            if len(filtered_response_lines) > 0:
                logger.info("{title:-^120}\n\n{lines}\n".format(
                    title=" Response Diff ",
                    lines="\n".join(filtered_response_lines)))
        return(request_diff_lines, response_diff_lines)

    def _start_log_diff(self, old_req, new_req, old_res, new_res):
        """Log enough diff metadata and let user decide what to do
        using log_diff method and then _end_log_diff is called to draw
        borders mostly

        Args:
            old_req (Request): Original Request.
            new_req (Request): Tampered Request.
            old_res (Response): Original Response.
            new_res (Response): Tampered Response.

        Returns:
            None

        """
        if self.LOG_DIFFS is True:
            logger.info(
                    "\n{title:=^120}\n\n"
                    "{old_identifier:^10}: {old_request} -> {old_response}\n"
                    "{new_identifier:^10}: {new_request} -> {new_response}\n".format(
                        title=" Tamper N Replay ",
                        old_identifier=getattr(old_req, self.IDENTIFIER_NAME, "Flow 1"),
                        old_request=old_req,
                        new_identifier=getattr(new_req, self.IDENTIFIER_NAME, "Flow 2"),
                        new_request=new_req,
                        old_response=old_res,
                        new_response=new_res
                    ))

    def _end_log_diff(self, message=" End TnR "):
        """End diff metadata

        Kwargs:
            message (str): Message to write to log

        Returns:
            None

        """
        if self.LOG_DIFFS is True:
            logger.info("\n{title:=^120}\n".format(title=message))

    def store_diff(self, path, old_req, new_req, old_res, new_res, overwrite=False):
        """Call log_diff and store the diff into files specified
        by path variable.

        Args:
            path (str): Path+".diff" to write the diff.
            old_req (Request): Original Request.
            new_req (Request): Tampered Request.
            old_res (Response): Original Response.
            new_res (Response): Tampered Response.

        Kwargs:
            overwrite (bool): Whether to overwrite if path already exists.

        Returns:
            None

        """
        self._start_log_diff(old_req, new_req, old_res, new_res)
        request_diff_lines, response_diff_lines = self.log_diff(old_req, new_req, old_res, new_res)

        if self.WRITE_TO_FILES is True:
            path = self.write_to_file(
                    path + ".diff",
                    "\n".join(itertools.chain(request_diff_lines, (i for i in ['']), response_diff_lines)), overwrite)

        self._end_log_diff(" {} ".format(path))

    def log_transaction(self, request, response):
        """Stringify request and response for logging and
        storing to file.

        Args:
            request (Request): Request to log.
            response (Response): Response to log.

        Returns:
            str: Stringified representation of request.
            str: Stringified representation of response.

        """
        return(self.stringify_request(request), self.stringify_response(response))

    def _start_log_transaction(self, request, response):
        """Start metadata to log the transaction, after this log_transaction
        is called followed by _end_log_transaction.

        Args:
            request (Request): Request to log.
            response (Response): Response to log.

        Returns:
            None

        """
        # Show a brief of request in log and let user pick what he wants
        if self.LOG_FLOWS:
            # Logging the stringified version of the request and response will clutter the log file,
            # so only show a brief representation in log file, but return the fill string versions
            # for the transaction files to be populated.
            logger.info("\n{title:=^120}\n{request} -> {response}\n".format(title="", request=request, response=response))

    def _end_log_transaction(self, message=""):
        """End metadata to log the transaction

        Kwargs:
            message (str): Message to write to log

        Returns:
            None

        """
        if self.LOG_FLOWS:
            logger.info("\n{title:=^120}\n".format(title=message))

    def store_transaction(self, path, request, response, overwrite=False):
        """Method to write HTTP transaction to disk after passing to log.

        Args:
            path (str): path+".http" for writing the HTTP transaction.
            request (Request): Request to store.
            response (Response): Response to store.

        Kwargs:
            overwrite (bool): Whether to overwrite if path already exists.

        Returns:
            None

        """
        self._start_log_transaction(request, response)
        request_str, response_str = self.log_transaction(request, response)

        message = ""  # Initialize message, so if at all file is written show it in end_log
        if self.WRITE_TO_FILES is True:
            self.write_to_file(
                path + ".http",
                request_str + "\n\n" + response_str,
                overwrite)
            self.write_to_file(
                path + ".curl",
                self.curlify(request),
                overwrite)
            # Modify message to contain path
            message = " {} ".format(path)

        self._end_log_transaction(message)

    def write_to_file(self, path, content, overwrite):
        """Write content to a file specified by path+integer. If overwrite is False,
        the file is saved with the next available integer.

        Args:
            path (str): Path of the file to write to.
            content (str): Content to be written.
            overwrite (bool): Whether to overwrite if path already exists.

        Returns:
            str: Path of the file written.

        """
        count = 0
        while (os.path.exists("{}.{}".format(path, count))):
            count += 1
        path += ".{}".format(max(0, count - 1) if overwrite is True else count)

        with open(path, "wb" if isinstance(content, bytes) else "w") as f:
            f.write(content)
        return(path)

    def get_unique_path(self, request):
        """Generate a unique path for a request based on its
        url and unique_id. Can be overridden by user if necessary.

        Note:
            All directories part of the path needs to be
            created before returning.

        Args:
            request (Request): Request.

        Returns:
            str: Unique path.

        """
        unique_id = self.get_unique_id(request)
        parsed_url = urllib.parse.urlparse(request.url)
        path_list = [self.OUTPUT_DIR, parsed_url.netloc] + parsed_url.path.replace("..", "__").strip("/").split("/")
        path = os.path.join(*path_list)
        os.makedirs(path, exist_ok=True)
        return(os.path.join(path, unique_id))

    def get_unique_id(self, request):
        """Generate unique id from request, can be overridden on wish.

        Args:
            request (Request): Request.

        Returns:
            str: Unique id.

        """
        return(hashlib.md5(self.stringify_request(request).encode("utf-8")).hexdigest())

    def curlify(self, request):
        """Curlify the given mitmproxy request.

        Args:
            request (Request): Request to be curlified.

        Returns:
            str: Curl command string.

        """
        curl = "curl -X {method} -d '{body}' {headers} '{url}'".format(
                method=request.method,
                body=self._escape_quotes(request.content.decode("utf-8").strip()),
                headers=" ".join(["-H '{hname}: {hvalue}'".format(
                                hname=self._escape_quotes(hname),
                                hvalue=self._escape_quotes(hvalue)) for hname, hvalue in request.headers.items()]),
                url=self._escape_quotes(request.url))
        return(curl)

    def stringify_request(self, request):
        """Stringify request

        Args:
            request (Request): Request to stringify.

        Returns:
            str: String representation of the given request.

        """
        return(self.stringify_request_meta(request) + self.stringify_request_body(request))

    def stringify_response(self, response):
        """Stringify response

        Args:
            response (Response): response to stringify.

        Returns:
            str: String representation of the given response.

        """
        return(self.stringify_response_meta(response) + self.stringify_response_body(response))


    def _generic_stringify_body(self, item):
        """Stringify request or response body content.

        Args:
            item (Request/Response): Request or Response to stringify.

        Returns:
            str: String representation of the given item's body.

        """
        string = ''
        if isinstance(item, (Request, Response)):
            if item.content is not None:
                string += item.content.decode("utf-8", "replace")
        return(string)

    def _generic_stringify_meta(self, item):
        """Stringify meta data part of request or response. i.e Everything except content

        Args:
            item (Request/Response): Request or Response to stringify.

        Returns:
            str: String representation of the given item's metadata.

        """
        string = None
        if isinstance(item, Request):
            string = "{method} {url} {version}\r\n".format(
                    method=item.method,
                    url=item.url,
                    version=item.http_version)
        elif isinstance(item, Response):
            string = "{version} {code} {status}\r\n".format(
                    version=item.http_version,
                    code=item.status_code,
                    status=item.reason)

        if isinstance(item, (Request, Response)):
            string += "{headers}\r\n"
            string = string.format(
                    headers="\r\n".join(["{hname}: {hvalue}".format(
                                hname=hname, hvalue=hvalue) for hname, hvalue in item.headers.items()]))
            string += "\r\n"
        return(string)



    def diff_request(self, request1, request2):
        """Simplest diff using python inbuilt differ.
        Can be overridden by user for complex cases (eg: Dealing with REST api).

        Args:
            request1 (Request): request 1.
            request2 (Request): request 2.

        Returns:
            generator: Yielding the diff line by line.

        """
        d = difflib.Differ()
        return(d.compare(self.stringify_request(request1).splitlines(), self.stringify_request(request2).splitlines()))

    def diff_response(self, response1, response2):
        """Simplest diff using python inbuilt differ.
        Can be overridden by user for complex cases (eg: Dealing with REST api).

        Args:
            response1 (Response): response 1.
            response2 (Response): response 2.

        Returns:
            generator: Yielding the diff line by line.

        """
        d = difflib.Differ()
        return(d.compare(self.stringify_response(response1).splitlines(), self.stringify_response(response2).splitlines()))

    def beautify_json(self, item):
        """Return string of neatly formatted json

        Args:
            item (str|list|dict): Object to be beautified by json

        Returns:
            str: Pretty JSON string

        """
        json_item = None

        if isinstance(item, str):
            try:
                json_item = json.loads(item)
            except json.decoder.JSONDecodeError as e:
                logger.info("Unable to decode a given string as JSON: {}".format(item))
        elif isinstance(item, (list, dict)):
            json_item = item

        return(json.dumps(json_item, sort_keys=True, indent=4) if json_item else None)

    def tamper_for_replay(self, request):
        """Should be implemented by child class.

        Args:
            request (Request): Response.

        Returns:
            Request: Tampered request.

        """
        return(request)

    def tamper_request(self, request):
        """Should be implemented by child class.

        Args:
            request (Request): Response.

        Returns:
            Request: Tampered request.

        """
        return(request)

    def tamper_response(self, response):
        """Should be implemented by child class.

        Args:
            response (Response): Response.

        Returns:
            Response: Tampered response.

        """
        return(response)

    def stringify_request_meta(self, request):
        """Stringify the entire non body part of a request.
        Can be user overridden.

        Args:
            request (Request): Request whose metadata needs to be stringified.

        Returns:
            str: String representation of the given item's metadata.

        """
        return(self._generic_stringify_meta(request))

    def stringify_response_meta(self, response):
        """Stringify the entire non body part of a response.
        Can be user overridden.

        Args:
            response (Response): Response whose metadata needs to be stringified.

        Returns:
            str: String representation of the given item's metadata.

        """
        return(self._generic_stringify_meta(response))

    def stringify_request_body(self, request):
        """Stringify the entire body part of a request.
        Can be user overridden.

        Args:
            request (Request): Request whose body needs to be stringified.

        Returns:
            str: String representation of the given item's body.

        """
        return(self._generic_stringify_body(request))

    def stringify_response_body(self, response):
        """Stringify the entire body part of a response.
        Can be user overridden

        Args:
            response (Response): Response whose body needs to be stringified.

        Returns:
            str: String representation of the given item's body.

        """
        return(self._generic_stringify_body(response))

    def set_identifier(self, item, value):
        """Set identifier on request to be used in diffs

        Args:
            item (Request): Mitmproxy request object
            value (str): A string to understand diffs easily (like normal user, moderator etc..)

        Returns: TODO

        """
        setattr(item, self.IDENTIFIER_NAME, value)
        return(item)
