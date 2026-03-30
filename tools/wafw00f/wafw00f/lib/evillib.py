#!/usr/bin/env python3
'''
Copyright (C) 2026, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

import time
import logging
from copy import copy
from urllib.parse import urlparse

import requests
import urllib3

# For requests < 2.16, this should be used.
# requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# For requests >= 2.16, this is the convention
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def_headers = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0',
    'Accept-Language': 'en-US,en;q=0.5',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'cross-site',
    'Priority': 'u=0, i',
    'DNT': '1',
}
proxies = {}

# Maximum response body size to read (100KB should be plenty for WAF detection)
MAX_RESPONSE_SIZE = 100 * 1024

class waftoolsengine:
    def __init__(
        self, target='https://example.com', debuglevel=0,
        path='/', proxies=None, redir=True, head=None, timeout=7
    ):
        self.target = target
        self.debuglevel = debuglevel
        self.requestnumber = 0
        self.path = path
        self.redirectno = 0
        self.allowredir = redir
        self.proxies = proxies
        self.log = logging.getLogger('wafw00f')
        self.timeout = timeout
        if head:
            self.headers = head
        else:
            self.headers = copy(def_headers) #copy object by value not reference. Fix issue #90

    def Request(self, headers=None, path=None, params={}, delay=0):
        try:
            time.sleep(delay)
            if not headers:
                h = self.headers
            else: h = headers

            # Create the url manually to avoid path normalization
            url = self.target if path is None else self.target.rstrip('/') + '/' + path.lstrip('/')
            prepared = requests.Request('GET', url, headers=h,
                                        params=params or {}).prepare()

            parsed_url = urlparse(prepared.url)

            # Ensuring trailing slash does not disappear
            trailing_slash = parsed_url.path.endswith('/')
            if trailing_slash and not url.endswith('/'):
                url += '/'

            # Preserve the original path (e.g. ../../etc/passwd)
            if params:
                prepared.url = url + '?' + parsed_url.query
            else:
                prepared.url = url

            req = requests.Session().send(prepared, proxies=self.proxies, timeout=self.timeout,
                    allow_redirects=self.allowredir, verify=False, stream=True)

            # Read only up to MAX_RESPONSE_SIZE to avoid hanging on streaming responses
            # (e.g., audio streams) - see issue #246
            # Also enforce timeout during reading to handle slow streaming servers
            chunks = []
            bytes_read = 0
            start_time = time.time()
            for chunk in req.iter_content(chunk_size=8192):
                chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read >= MAX_RESPONSE_SIZE:
                    break
                # Check if we've exceeded the timeout during reading
                if time.time() - start_time > self.timeout:
                    self.log.debug('Timeout reached during response body reading')
                    break
            req._content = b''.join(chunks)
            self.log.info('Request Succeeded')
            self.log.debug('Headers: %s\n' % req.headers)
            self.log.debug('Content: %s\n' % req.content)
            self.requestnumber += 1
            return req
        except requests.exceptions.RequestException as e:
            self.log.error('Something went wrong %s' % (e.__str__()))
