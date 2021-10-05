#!/usr/bin/env pypy3

"""
Produce the report in draft-nottingham-binary-structurd-headers
"""

from collections import defaultdict
from operator import itemgetter
import sys


from header_runner import Runner


class SHReport(Runner):
    def __init__(self):
        Runner.__init__(self)
        self.succeed = defaultdict(int)
        self.failure = defaultdict(int)
        self.seen = defaultdict(int)

    def analyse(self, raw_headers, parsed_headers, parse_errors):
        for name in raw_headers:
            self.seen[name] += 1
        for name in parsed_headers:
            self.succeed[name] += 1
        for name in parse_errors:
            self.failure[name] += 1

    def show(self):
        allAttempted = list(set(list(self.succeed.keys()) + list(self.failure.keys())))
        allAttempted.sort()
        longestName = max([len(n) for n in list(self.succeed.keys()) + list(self.failure.keys())])
        maxDigits = len(f"{max(list(self.succeed.values() or [0]) + list(self.failure.values() or [0])):,}")
        print()
        print(f"* Requests: {checker.cursor:n}")
        print("* Parsing Results (succeed / fail)")
        for header in allAttempted:
            success = self.succeed.get(header, 0)
            fail = self.failure.get(header, 0)
            failrate = fail / (success + fail)
            print(f"{header.decode('ascii'):<{longestName}} {success:>{maxDigits},} / {fail:>{maxDigits},} = {failrate:>8.3%}")
        print()
        print("* Top 100 Headers")
        seen = sorted(self.seen.items(), key=itemgetter(1))
        seen.reverse()
        for (header, count) in seen[:100]:
            print(f"  - {header.decode('ascii')}: {count:n}")


if __name__ == "__main__":
    checker = SHReport()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        pass
    checker.show()
