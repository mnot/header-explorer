#!/usr/bin/env pypy3

from collections import defaultdict
from decimal import Decimal
import difflib
from functools import partial, lru_cache
from itertools import chain
from operator import itemgetter
import sys


from header_runner import Runner


class CC(Runner):

    INTERESTING = [b"cache-control"]
    DEFINED_DIRECTIVES = [
        "max-age",
        "s-maxage",
        "public",
        "private",
        "no-store",
        "no-cache",
        "must-revalidate",
        "no-transform",
        "proxy-revalidate",
        "stale-if-error",
        "stale-while-revalidate",
        "immutable",
    ]
    INFORMAL_DIRECTIVES = ["pre-check", "post-check"]
    REQUEST_DIRECTIVES = ["max-stale", "min-fresh", "only-if-cached"]
    MAXAGE_DIRECTIVES = ["max-age", "s-maxage"]
    SMALL = 60
    MAXAGE_CLASHES = set(["no-store", "no-cache"])
    PUBLIC_CLASHES = set(["max-age", "s-maxage", "no-store", "private"])
    SHOW_DIRECTIVES = 25
    SHOW_SAMPLES = 10
    SIMILARITY_RATIO = 0.8

    def __init__(self):
        Runner.__init__(self)
        self.parse_succeed = 0
        self.parse_fail = 0
        self.directive_count = 0
        self.defined_directives = defaultdict(int)
        self.informal_directives = defaultdict(int)
        self.request_directives = defaultdict(int)
        self.misspelled_directives = defaultdict(int)
        self.misspelled_samples = defaultdict(lambda: defaultdict(int))
        self.misspelled_directives_by_origin = defaultdict(lambda: defaultdict(int))
        self.other_directives = defaultdict(int)

        self.directives_by_origin = defaultdict(lambda: defaultdict(int))
        self.total_origins = 0

        self.param_counts = defaultdict(int)
        self.maxage_count = 0
        self.maxage_small = defaultdict(int)
        self.maxage_overflow = 0
        self.maxage_decimal = 0
        self.maxage_negative = 0
        self.maxage_nonnumeric = 0
        self.maxage_nonnumeric_sample = defaultdict(int)
        self.maxage_clash = 0
        self.maxage_conflicting = 0
        self.public_clash = 0

        self.total_headers = 0
        self.dir_digits = 15
        self.KNOWN_DIRECTIVES = (
            self.DEFINED_DIRECTIVES + self.REQUEST_DIRECTIVES + self.INFORMAL_DIRECTIVES
        )

    def parsed(self, url, url_origin, name, parsed, raw_value):
        self.parse_succeed += 1
        for directive in parsed:
            self.directive_count += 1
            self.directives_by_origin[directive][url_origin] += 1
            if directive in self.DEFINED_DIRECTIVES:
                self.defined_directives[directive] += 1
            elif directive in self.INFORMAL_DIRECTIVES:
                self.informal_directives[directive] += 1
            elif directive in self.REQUEST_DIRECTIVES:
                self.request_directives[directive] += 1
            else:
                similar_directive = self.find_similar(directive)
                if similar_directive:
                    self.misspelled_directives[similar_directive] += 1
                    self.misspelled_samples[similar_directive][directive] += 1
                    self.misspelled_directives_by_origin[similar_directive][
                        url_origin
                    ] += 1
                else:
                    self.other_directives[directive] += 1

            params = parsed[directive][1]
            if params:
                for param in params:
                    self.param_counts[param] += 1

            if directive in self.MAXAGE_DIRECTIVES:
                self.maxage_count += 1
                maxage_is_int = False
                maxage_value = parsed[directive][0]

                if isinstance(maxage_value, int):
                    maxage_is_int = True
                    if -self.SMALL <= maxage_value <= self.SMALL:
                        self.maxage_small[maxage_value] += 1
                    elif not -(2 ** 31) <= maxage_value <= 2 ** 31:
                        self.maxage_overflow += 1
                    if maxage_value < 0:
                        self.maxage_negative += 1
                elif isinstance(maxage_value, Decimal):
                    self.maxage_decimal += 1
                else:
                    self.maxage_nonnumeric += 1
                    self.maxage_nonnumeric_sample[
                        f"{maxage_value} ({type(maxage_value)})"
                    ] += 1

                if self.MAXAGE_CLASHES.intersection(parsed):
                    self.maxage_clash += 1
                    if maxage_is_int and maxage_value > 0:
                        self.maxage_conflicting += 1

            if directive == "public":
                if self.PUBLIC_CLASHES.intersection(parsed):
                    self.public_clash += 1

    def raw(self, url, url_origin, name, value, why):
        if why != "unrecognised":
            self.parse_fail += 1

    def show(self):
        print(f"* Total header sets: {self.cursor:n}")
        self.total_headers, hdr_rate = self.compare(self.parse_fail, self.parse_succeed)
        hdr_digits = len(f"{self.total_headers:n}")

        origins = set()
        origins.update(
            chain.from_iterable([v.keys() for v in self.directives_by_origin.values()])
        )
        self.total_origins = len(origins)

        print(f"* Cache-Control Headers")
        print(f"  {self.total_headers:{hdr_digits}n} Cache-Control headers total")
        print(f"  {self.parse_succeed:{hdr_digits}n} headers successfully parsed")
        print(f"  {self.parse_fail:{hdr_digits}n} headers failed parsing")
        print(
            f"  {self.too_long:{hdr_digits}n} headers had values that were too long to be reliable"
        )
        print(f"  {self.empty:{hdr_digits}n} headers had empty values")
        print(f"  {hdr_rate:1.3f}% failed to parse")
        print(f"  {self.total_origins:{hdr_digits}n} total origins")
        print()

        self.dir_digits = len(f"{self.directive_count:n}")
        self.padding = " " * self.dir_digits

        print(f"* Cache Directives")
        print(f"  {self.directive_count:{self.dir_digits}n} cache directives total")
        print()

        self.summarise("Defined Response Directives", self.defined_directives)
        self.summarise("Informal Directives", self.informal_directives)
        self.summarise("Request Directives", self.request_directives)
        self.summarise(
            "Misspelled Directives",
            self.misspelled_directives,
            self.misspelled_samples,
            self.misspelled_directives_by_origin,
        )
        self.summarise("Unrecognised Directives", self.other_directives)

        print(f"* Maxage bad values (% of [s]max-age directives)")
        mar = partial(self.rate, whole=self.maxage_count)
        print(
            f"  - {self.maxage_overflow:{hdr_digits}n} overflows "
            + f"({mar(self.maxage_overflow):1.3f}%)"
        )
        print(
            f"  - {self.maxage_decimal:{hdr_digits}n} decimal values "
            + f"({mar(self.maxage_decimal):1.3f}%)"
        )
        print(
            f"  - {self.maxage_negative:{hdr_digits}n} negative values "
            + f"({mar(self.maxage_negative):1.3f}%)"
        )
        print(
            f"  - {self.maxage_nonnumeric:{hdr_digits}n} non-numeric values "
            + f"({mar(self.maxage_nonnumeric):1.3f}%)"
        )
        for name, value in sorted(
            self.maxage_nonnumeric_sample.items(), key=itemgetter(1), reverse=True
        )[: self.SHOW_SAMPLES]:
            print(f"{self.padding}    - {name}, {value:n}")
        print()
        print(f"* Clashing directives")
        maxage_clash_rate = self.rate(self.maxage_clash, self.maxage_count)
        print(
            f"  - {self.maxage_clash:n} with [s]max-age and conflicting directives present"
            + f"({maxage_clash_rate:1.3f}% of responses with [s]max-age)"
        )
        public_clash_rate = self.rate(
            self.public_clash, self.defined_directives["public"]
        )
        print(
            f"  - {self.public_clash:n} with public and conflicting directives"
            + f"({public_clash_rate:1.3f}% of responses with public)"
        )

    def summarise(self, title, results, samples=None, origins=None):
        if not origins:
            origins = self.directives_by_origin
        if len(results) > self.SHOW_DIRECTIVES:
            print(f"* {title} (top {self.SHOW_DIRECTIVES})")
        else:
            print(f"* {title}")
        for name, value in sorted(results.items(), key=itemgetter(1), reverse=True)[
            : self.SHOW_DIRECTIVES
        ]:
            origin_count = len(origins[name])
            print(
                f"  - {value:{self.dir_digits}n} {name} "
                + f"({self.rate(value, self.total_headers):1.3f}% of CC headers seen "
                + f"on {origin_count} / {self.rate(origin_count, self.total_origins):1.3f}% of origins)"
            )
            if samples:
                sample = ", ".join(
                    [
                        f"{n} ({v})"
                        for n, v in sorted(
                            samples[name].items(), key=itemgetter(1), reverse=True
                        )
                    ][: self.SHOW_SAMPLES]
                )
                print(f"     {self.padding}{sample}")
        print()

    @staticmethod
    def rate(part, whole):
        if whole:
            return part / whole * 100
        else:
            return 0

    def compare(self, a, b):
        whole = a + b
        return whole, self.rate(a, whole)

    @lru_cache(maxsize=2 ** 12)
    def find_similar(self, directive_name):
        highest_similarity = 0
        candidate = None
        for defined_directive in self.KNOWN_DIRECTIVES:
            similarity = difflib.SequenceMatcher(
                None, defined_directive, directive_name
            ).ratio()
            if self.SIMILARITY_RATIO < similarity > highest_similarity:
                highest_similarity = similarity
                candidate = defined_directive
        return candidate


if __name__ == "__main__":
    checker = CC()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        print()
    checker.show()
