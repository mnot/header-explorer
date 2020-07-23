#!/usr/bin/env pypy3

import csv
import functools
import gzip
import locale
from struct import unpack_from, error as structError
import sys
from time import time

from http_sfv import structures, __version__ as sfv_version

locale.setlocale(locale.LC_ALL, "")


class Runner:

    INTERESTING = []
    BUFSIZE = 2 ** 29
    TICK = 100000
    HEADERMAP = {  # see https://mnot.github.io/I-D/binary-structured-headers/
        b"accept": "list",
        b"accept-encoding": "list",
        b"accept-language": "list",
        b"accept-patch": "list",
        b"accept-ranges": "list",
        b"access-control-allow-credentials": "item",
        b"access-control-allow-headers": "list",
        b"access-control-allow-methods": "list",
        b"access-control-allow-origin": "item",
        b"access-control-max-age": "item",
        b"access-control-request-headers": "list",
        b"access-control-request-method": "item",
        b"age": "item",
        b"allow": "list",
        b"alpn": "list",
        b"alt-svc": "dictionary",
        b"alt-used": "item",
        b"cache-control": "dictionary",
        b"connection": "list",
        b"content-encoding": "list",
        b"content-language": "list",
        b"content-length": "item",
        b"content-type": "item",
        b"expect": "item",
        b"expect-ct": "dictionary",
        b"forwarded": "dictionary",
        b"host": "item",
        b"keep-alive": "dictionary",
        b"origin": "item",
        b"pragma": "dictionary",
        b"prefer": "dictionary",
        b"preference-applied": "dictionary",
        b"retry-after": "item",
        b"strict-transport-security": "dictionary",
        b"surrogate-control": "dictionary",
        b"te": "list",
        b"trailer": "list",
        b"transfer-encoding": "list",
        b"vary": "list",
        b"x-content-type-options": "item",
        b"x-xss-protection": "list",
    }

    def __init__(self):
        self.cursor = 0
        self.uninteresting = 0
        self.too_long = 0
        self.empty = 0

    def run(self, filename):
        # bring some things into the local namespace for a tight loop.
        now = time()
        TICK = self.TICK
        BUFSIZE = self.BUFSIZE
        parseHeader = self.parseHeader
        analyse = self.analyse
        with gzip.open(filename, "rb") as headerfile:
            raw_headers, parsed_headers, parse_errors = {}, {}, {}
            buf = bytearray(BUFSIZE)
            view = memoryview(buf)
            headerfile.readinto(buf)
            offset = 0
            while True:
                try:
                    nameLen, valueLen = unpack_from("!HH", view, offset)
                    offset += 4
                    name, value = unpack_from(f"!{nameLen}s{valueLen}s", view, offset)
                    offset += (nameLen + valueLen)
                except structError:
                    sys.stderr.write("* READ\n")
                    offset = headerfile.readinto(buf)
                    if offset == 0:
                        break
                    else:
                        continue
                if name == b"":  # new block
                    self.cursor += 1
                    if self.cursor % TICK == 0:
                        last = now
                        now = time()
                        delta = now - last
                        rate = int(TICK / delta)
                        sys.stderr.write(f"- response {self.cursor:n} ({rate:n}/s)\n")
                    analyse(raw_headers, parsed_headers, parse_errors)
                    raw_headers, parsed_headers, parse_errors = {}, {}, {}
                else:
                    raw_headers[name] = value
                    try:
                        parsed = self.parseHeader(name, value)
                        if parsed is not None:
                            parsed_headers[name] = parsed
                    except ValueError as why:
                        parse_errors[name] = why

    def analyse(self, raw_headers, parsed_headers, parse_errors):
        raise NotImplementedError

    def parseHeader(self, name, value):
        if self.INTERESTING and name not in self.INTERESTING:
            self.uninteresting += 1
            return
        if len(value) > 254:
            self.too_long += 1
            return  # we skip oversized headers because they could be truncated
        if value.isspace():
            self.empty += 1
            return  # we don't consider empty headers to be a problem
        if name not in self.HEADERMAP:
            return
        return self._parseHeader(name, value)

    @functools.lru_cache(maxsize=2 ** 15)
    def _parseHeader(self, name, value):
        structure = structures[self.HEADERMAP[name]]()
        structure.parse(value)
        return structure

