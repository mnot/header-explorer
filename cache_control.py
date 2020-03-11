#!/usr/bin/env pypy3

from collections import defaultdict
from operator import itemgetter
import sys


from header_runner import Runner


class CC(Runner):

    INTERESTING = [b"cache-control"]

    def __init__(self):
        Runner.__init__(self)
        self.directives = defaultdict(int)
        self.succeed = 0
        self.failure = 0

    def parsed(self, url, name, parsed):
        self.succeed += 1
        for directive in parsed:
            if "\0" in directive:
                sys.stderr.write(f" - {directive} - {url}\n")
            self.directives[directive] += 1

    def raw(self, url, name, value, why):
        if why != "unrecognised":
            self.failure += 1

    def show(self):
        print("* Parsing Results (succeed / fail)")
        failrate = 0
        if self.failure:
            failrate = "%1.3f" % (self.failure / (self.succeed + self.failure) * 100)
        print(f"  - Cache-Control: {self.succeed:n} / {self.failure:n} = {failrate}%")
        print()
        print("* Directives")
        for name, value in sorted(
            checker.directives.items(), key=itemgetter(1), reverse=True
        ):
            print(f"  - {name} - {value:n}")


if __name__ == "__main__":
    checker = CC()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        pass
    checker.show()
