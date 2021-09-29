#!/usr/bin/env pypy3

"""
Find header fields in the dataset that aren't registered with IANA.
"""

from collections import Counter, defaultdict
from operator import itemgetter
import sys
from xml.etree import ElementTree

import requests

from header_runner import Runner


REGISTRY_URL = "https://www.iana.org/assignments/message-headers/message-headers.xml"
ns = {"iana": "http://www.iana.org/assignments"}


class Unregistered(Runner):
    INTERESTING_VALUES = [b"surrogate-key"]

    def __init__(self):
        Runner.__init__(self)
        self.unregistered = Counter()
        self.servers = defaultdict(Counter)
        self.registered = self.get_registered()
        self.registered.update({b":url", b":origin"})

    def analyse(self, raw_headers, parsed_headers, parse_errors):
        server_name = raw_headers.get(b"server", b"-")
        for header_name in raw_headers:
            if header_name not in self.registered:
                self.unregistered[header_name] += 1
            if header_name in self.INTERESTING_VALUES:
                self.servers[header_name][server_name] += 1

    def show(self):
        print("* Top Interesting Header Servers")
        for header_name, servers in self.servers.items():
            print(f"  - {header_name.decode('ascii')}")
            for server, value in servers.most_common()[:50]:
                print(f"    {value:n} - {server.decode('ascii')}")
        print()
        print("* Top Unregistered Headers Seen")
        for name, value in self.unregistered.most_common()[:50]:
            print(f"  - {name.decode('utf-8')} {value:n}")

    def get_registered(self):
        registered = []
        registry_xml = requests.get(REGISTRY_URL)
        registry = ElementTree.fromstring(registry_xml.content)
        for record in registry.iter(f"{{{ns['iana']}}}record"):
            try:
                if record.find("iana:protocol", ns).text == "http":
                    registered.append(
                        record.find("iana:value", ns)
                        .text.strip()
                        .lower()
                        .encode("ascii")
                    )
            except AttributeError:
                continue
        return set(registered)


if __name__ == "__main__":
    checker = Unregistered()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        print()
    checker.show()
