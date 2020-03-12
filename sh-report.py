#!/usr/bin/env pypy3

from collections import defaultdict
from operator import itemgetter
import sys


from header_runner import Runner


class CC(Runner):

    def __init__(self):
        Runner.__init__(self)
        self.succeed = defaultdict(int)
        self.failure = defaultdict(int)
        self.skipped = defaultdict(int)

    def parsed(self, url, name, parsed):
        self.succeed[name] += 1

    def raw(self, url, name, value, why):
        if why != "unrecognised":
            self.failure[name] += 1
        else:
            self.skipped[name] += 1

    def show(self):
        allAttempted = list(
            set(list(self.succeed.keys()) + list(self.failure.keys()))
        )
        allAttempted.sort()
        print()
        print(f"* Requests: {checker.cursor:n}")
        print("* Parsing Results (succeed / fail)")
        for header in allAttempted:
            success = self.succeed.get(header, 0)
            fail = self.failure.get(header, 0)
            failrate = "%1.3f" % (fail / (success + fail) * 100)
            print(f"  - {header.decode('ascii')}: {success:n} / {fail:n} = {failrate}%")
        print()
        print("* Top 50 Skipped Headers")
        skipped = sorted(self.skipped.items(), key=itemgetter(1))
        skipped.reverse()
        for (header, count) in skipped[:50]:
            print(f"  - {header.decode('ascii')}: {count:n}")


if __name__ == "__main__":
    checker = CC()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        pass
    checker.show()
