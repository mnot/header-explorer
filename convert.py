#!/usr/bin/env pypy3

"""
Convert the HTTP response headers in the CSV request files at:
  https://legacy.httparchive.org/downloads.php
... into an efficient-to-read binary format.
"""

import gzip
import locale
from struct import pack
import sys
from time import time

TICK = 100000

locale.setlocale(locale.LC_ALL, "")


def run(args):
    cursor = 0
    out = []
    now = time()
    other = args.other
    prefix = ""
    with gzip.open(args.output_file, "wb") as outfile:
        with gzip.open(args.input_file, "rt", newline="", errors="replace") as csvfile:
            for line in csvfile:
                cursor += 1
                if line[-2] == "\\":
                    prefix += line
                    continue
                if prefix:
                    line = prefix + line
                    prefix = ""
                row = parseln(line)
                if cursor % TICK == 0:
                    last = now
                    now = time()
                    delta = now - last
                    rate = int(TICK / delta)
                    sys.stderr.write(f"- row {cursor:n} ({rate:n}/s)\n")
                    outfile.write(b"".join(out))
                    out = []
                getHdr(out, ":url", row[6])
                getHdr(out, "accept-ranges", row[34])
                getHdr(out, "age", row[35])
                getHdr(out, "cache-control", row[36])
                getHdr(out, "connection", row[37])
                getHdr(out, "content-encoding", row[38])
                getHdr(out, "content-language", row[39])
                getHdr(out, "content-length", row[40])
                getHdr(out, "content-location", row[41])
                getHdr(out, "content-type", row[42])
                getHdr(out, "date", row[43])
                getHdr(out, "etag", row[44])
                getHdr(out, "expires", row[45])
                getHdr(out, "keep-alive", row[46])
                getHdr(out, "last-modified", row[47])
                getHdr(out, "location", row[48])
                getHdr(out, "pragma", row[49])
                getHdr(out, "server", row[50])
                getHdr(out, "transfer-encoding", row[51])
                getHdr(out, "vary", row[52])
                getHdr(out, "via", row[53])
                getHdr(out, "x-powered-by", row[54])
                if other:
                    parseOtherHdrs(out, row[23])
                out.append(writeln("", ""))


def parseln(line):
    quoted = False
    escaped = False
    row = []
    buf = []
    for char in line:
        if escaped:
            if char is "N":
                buf.append(None)
            elif char is "0":
                buf.append(", ")
            elif char in ['"', "\\"]:
                buf.append(char)
            else:
                sys.stderr.write(f"* escaped {repr(char)}\n")
                buf.append(char)
            escaped = False
        else:
            if char is "\\":
                escaped = True
            elif not quoted and char is ",":
                if buf == [None]:
                    row.append(None)
                else:
                    row.append("".join(buf))
                buf = []
            elif char is '"':
                quoted = not quoted
            else:
                buf.append(char)
        assert not quoted, line
        assert not escaped, line
        assert len(row) == 60, line
    return row


def writeln(name, value):
    name = name.encode("latin-1", "replace")
    value = value.encode("latin-1", "replace")
    return pack(f"!HH{len(name)}s{len(value)}s", len(name), len(value), name, value)


def getHdr(out, name, value):
    if value is None:
        return
    out.append(writeln(name, value))


def parseOtherHdrs(out, otherValue):
    otherHeaders = {}
    lastHeader = None
    candidates = otherValue.split(",")
    for candidate in candidates:
        name, value = parseCandidate(candidate)
        if name is None:
            try:
                otherHeaders[lastHeader] += value
            except KeyError:
                sys.stderr.write(
                    f"- LOG PARSE ERROR (other header {lastHeader}): {otherValue}\n"
                )
        else:
            otherHeaders[name] = value
            lastHeader = name
    for name, value in otherHeaders.items():
        out.append(writeln(name, value))


def parseCandidate(candidate):
    if " = " in candidate:
        k, v = candidate.split(" = ", 1)
        key = k.strip().lower()
        if key == "":
            return None, f",{candidate}"
        else:
            return key, v.strip()
    else:
        return None, f",{candidate}"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract headers from HTTP Archive CSV dumps."
    )
    parser.add_argument(
        "-o",
        "--other_headers",
        dest="other",
        action="store_true",
        help="Extract other headers (see caveats in README)",
    )
    parser.add_argument("input_file", help="The HTTP Archive CSV dump file location")
    parser.add_argument("output_file", help="The desired output file location")
    args = parser.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        pass
