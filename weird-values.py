#!/usr/bin/env pypy3

"""
Produce the report in draft-nottingham-binary-structurd-headers
"""

from collections import defaultdict, Counter
from operator import itemgetter
import sys


from header_runner import Runner


class WeirdValues(Runner):
    def __init__(self, field_name):
        Runner.__init__(self)
        self.field_name = field_name.lower().encode("ascii")
        self.weird = defaultdict(Counter)

    def analyse(self, raw_headers, parsed_headers, parse_errors):
        if self.field_name in parse_errors:
            self.weird[str(parse_errors[self.field_name])][
                raw_headers[self.field_name].decode("ascii", "replace")
            ] += 1

    def show(self):
        for error_type in self.weird:
            print(f"* {error_type}")
            for error_value, count in self.weird[error_type].most_common()[:10]:
                print(f"  {count}: {error_value}")
            print()


if __name__ == "__main__":
    checker = WeirdValues(sys.argv[2])
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        pass
    checker.show()
