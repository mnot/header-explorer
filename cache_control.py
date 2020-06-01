#!/usr/bin/env pypy3

from collections import defaultdict, Counter
from decimal import Decimal
import difflib
from functools import partial, lru_cache
from itertools import chain
from operator import itemgetter
import sys


from header_runner import Runner

CC = b"cache-control"


class CacheControl(Runner):

    INTERESTING = [b"cache-control", b"content-type"]
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
    COINCIDENT_DIRECTIVES = {
        "public unnecessary": ("public", frozenset({"max-age", "s-maxage"})),
        "public conflicting": ("public", frozenset({"no-cache", "no-store"})),
        "must-revalidate unnecessary": (
            "must-revalidate",
            frozenset({"no-store", "no-cache"}),
        ),
        "must-revalidate conflicting": (
            "must-revalidate",
            frozenset({"stale-while-revalidate", "stale-if-error"}),
        ),
    }
    SHOW_DIRECTIVES = 25
    SHOW_SAMPLES = 5
    SIMILARITY_RATIO = 0.8

    def __init__(self):
        Runner.__init__(self)
        self.parse_succeed = 0
        self.parse_fail = 0
        self.directive_count = 0
        self.defined_directives = Counter()
        self.informal_directives = Counter()
        self.request_directives = Counter()
        self.misspelled_directives = Counter()
        self.misspelled_samples = defaultdict(lambda: Counter())
        self.misspelled_directives_by_origin = defaultdict(lambda: Counter())
        self.other_directives = Counter()
        self.other_directives_by_origin = defaultdict(lambda: Counter())

        self.directives_by_origin = defaultdict(lambda: Counter())
        self.content_types = Counter()
        self.directives_by_type = defaultdict(lambda: Counter())
        self.total_origins = 0

        self.coincidences = Counter()

        self.param_counts = Counter()
        self.maxage_count = 0
        self.maxage_small = Counter()
        self.maxage_overflow = 0
        self.maxage_decimal = 0
        self.maxage_negative = 0
        self.maxage_nonnumeric = 0
        self.maxage_nonnumeric_sample = Counter()
        self.maxage_clash = 0
        self.maxage_conflicting = 0

        self.total_headers = 0
        self.dir_digits = 15
        self.KNOWN_DIRECTIVES = (
            self.DEFINED_DIRECTIVES + self.REQUEST_DIRECTIVES + self.INFORMAL_DIRECTIVES
        )

    def analyse(self, raw_headers, parsed_headers, parse_errors):
        if CC not in raw_headers:
            return
        if CC not in parsed_headers:
            if parse_errors.get(CC, None):
                self.parse_fail += 1
            return

        url = raw_headers.get(b":url", "")
        url_origin = raw_headers.get(b":origin", "http://unknown:80/")
        try:
            content_type = parsed_headers.get(b"content-type", ["unknown"])[0]
        except AttributeError:
            content_type = "unknown"
        self.content_types[content_type] += 1
        parsed = parsed_headers[CC]
        self.parse_succeed += 1
        maxage_found = False
        maxage_conflict_found = False

        for (
            name,
            (directive, conflicting_directives),
        ) in self.COINCIDENT_DIRECTIVES.items():
            if directive in parsed and conflicting_directives.intersection(parsed):
                self.coincidences[name] += 1

        for directive in parsed:
            self.directive_count += 1
            self.directives_by_origin[directive][url_origin] += 1
            self.directives_by_type[content_type][directive] += 1
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
                    self.other_directives_by_origin[directive][url_origin] += 1

            params = parsed[directive][1]
            if params:
                for param in params:
                    self.param_counts[param] += 1

            if directive in self.MAXAGE_DIRECTIVES:
                if not maxage_found:
                    self.maxage_count += 1
                    maxage_found = True
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

                if (
                    self.MAXAGE_CLASHES.intersection(parsed)
                    and not maxage_conflict_found
                ):
                    maxage_conflict_found = True
                    if maxage_is_int and maxage_value > 0:
                        self.maxage_conflicting += 1
                    else:
                        self.maxage_clash += 1

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

        self.summarise(
            "Defined Response Directives",
            self.defined_directives,
            origins=self.directives_by_origin,
            sample_cleanup=self.pretty_origin,
        )
        self.summarise(
            "Informal Directives",
            self.informal_directives,
            origins=self.directives_by_origin,
            sample_cleanup=self.pretty_origin,
        )
        self.summarise(
            "Request Directives",
            self.request_directives,
            origins=self.directives_by_origin,
            sample_cleanup=self.pretty_origin,
        )
        self.summarise(
            "Misspelled Directives",
            self.misspelled_directives,
            self.misspelled_samples,
            origins=self.misspelled_directives_by_origin,
        )
        self.summarise(
            "Unrecognised Directives",
            self.other_directives,
            self.other_directives_by_origin,
            origins=self.directives_by_origin,
            sample_cleanup=self.pretty_origin,
        )

        self.summarise(
            "Directives by Content Type", self.content_types, self.directives_by_type,
        )

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
        print(f"* Conflicting directives")
        self.show_conflict(
            "max-age",
            self.MAXAGE_CLASHES,
            self.maxage_conflicting,
            self.maxage_count,
            "[s]max-age=0",
        )
        self.show_coincidence("public conflicting")
        self.show_coincidence("must-revalidate conflicting")

        print()
        print(f"* Unnecessary directives")
        self.show_conflict(
            "max-age",
            self.MAXAGE_CLASHES,
            self.maxage_clash,
            self.maxage_count,
            "[s]max-age=0",
        )
        self.show_coincidence("public unnecessary")
        self.show_coincidence("must-revalidate unnecessary")

    def show_coincidence(self, name):
        directive_name, clashing_directives = self.COINCIDENT_DIRECTIVES[name]
        self.show_conflict(directive_name, clashing_directives, self.coincidences[name])

    def show_conflict(
        self,
        directive_name,
        clashing_directives,
        clash_count=None,
        directive_count=None,
        display_name=None,
    ):
        if not display_name:
            display_name = directive_name
        if not directive_count:
            directive_count = self.defined_directives[directive_name]
        conflict_rate = self.rate(clash_count, directive_count)
        print(
            f"  - {clash_count:n} with {display_name} "
            + f"and one of {', '.join(clashing_directives)} "
            + f"({conflict_rate:1.3f}% of responses with {display_name})"
        )

    def summarise(
        self, title, results, samples=None, origins=None, sample_cleanup=lambda a: a
    ):
        total_directives = sum(results.values())
        extra = ""
        if len(results) > self.SHOW_DIRECTIVES:
            extra = f" (top {self.SHOW_DIRECTIVES})"
        rate = self.rate(total_directives, self.directive_count)
        print(f"* {title}{extra} - {total_directives:n} ({rate:1.3f}%)")
        for name, value in results.most_common(self.SHOW_DIRECTIVES):
            print(
                f"  - {value:{self.dir_digits}n} {name} "
                + f"({self.rate(value, self.total_headers):1.3f}%",
                end="",
            )
            if origins:
                origin_count = len(origins[name])
                origin_rate = self.rate(origin_count, self.total_origins)
                print(f" on {origin_count:n} / {origin_rate:1.3f}% of origins)")
            else:
                print(")")
            if samples:
                sample = ", ".join(
                    [
                        f"{sample_cleanup(n)} ({v:n}/{int(v/value*100)}%)"
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

    @lru_cache(maxsize=2 ** 8)
    def pretty_origin(self, origin):
        try:
            return origin.split("/", 3)[2].split(":", 1)[0]
        except IndexError:
            return "unknown"

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
    checker = CacheControl()
    try:
        checker.run(sys.argv[1])
    except KeyboardInterrupt:
        print()
    checker.show()
