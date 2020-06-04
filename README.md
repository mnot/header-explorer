
# Extracting Headers from the HTTP Archive

_...for Fun and Profit._

These scripts allow examination of the headers captured by the [HTTP Archive](https://httparchive.org) to extract interesting information about them.

Headers that can be parsed as [Structured Fields](https://httpwg.org/http-extensions/draft-ietf-httpbis-header-structure.html) are presented as structured data, to 

## Step 1: Preparation

First, you'll need to download a dump from the [HTTP Archive Downloads page](https://legacy.httparchive.org/downloads.php). In particular, you'll need a CSV dump for requests (not pages).

These are typically between 50G and 90G, so *make sure you have enough local disk space*.

Then, you'll need to convert it into a format that just contains the headers (plus the request URL, as a header called `:url`) in a binary gzip'd format (to make subsequent analysis more efficient). For example:

> ./convert.py httparchive_Feb_1_2020_requests.csv.gz core-headers.gz

... will create a file `core-headers.gz` that can be used in subsequent steps.

Depending on the size of the file and your computer, this will take a while; on my Macbook Pro (~2017), it processes about 17,000 rows per second. Make sure you have enough space for the output file (which will be smaller than the CSV dump).

If you pass the `-o` argument to `convert.py`, it will include "other" headers.

### About "Other" Headers

The HTTP Archive dumps a number of common HTTP headers into their own fields  (see [the schema](https://legacy.httparchive.org/downloads/httparchive_schema.sql)) in the CSV, relegating less common (or interesting, to them) headers into a catch-all "other headers" field. 

Unfortunately, they are dumped together in a way that's difficult to parse; while we can typically extract the other headers correctly, there's a good chance that at least a few "other" headers will get garbled.

So, by including these headers (with the `-o` argument), you'll have less reliable results, and also make the headers file larger.

In short, if you want to look at these headers, you'll need to pass `-o`; otherwise, it's probably best not to.

## Step 2: Write a Program

Next, you need to write a program that subclasses the `Runner` object in `header_runner.py` and overrides the `analyse` method. It is called once for header header section.

See `cache_control.py` for an example.

A few things to keep in mind:

* Field names are binary (to avoid the overhead of decoding them); urls and raw values are unicode strings
* Make sure you use `#!/usr/bin/env pypy3`; it's quite a bit faster
* Make sure you `Runner.__init__(self)` if you override `__init__`
* Runner.INTERESTING is a list of field names (binary!) that are fed into `parsed_headers`
* `:url` and `:origin` are special fields in the raw header dictionary
* Keep in mind that you're running in a very tight loop; there's [some good advice for this](https://codereview.stackexchange.com/questions/117080/efficiently-processing-large-100-mb-structured-binary-data-in-python-3) on the Internet

## Step 3: Profit

Now it's time to run the program. By default, it will use a LOT of memory (~2G) and all of one core (multiprocessing doesn't appear to be worth it; if you find different, please send a patch).

You can tune how much memory it uses by adjusting `Runner.BUFSIZE` in your subclass; lower values will impact efficiency.

On my ~2017 Macbook Pro, running a simple script that processes one header can do so at about 325,000 responses a second; the more complex `cache_control.py` script runs at about 180,000 responses a second.

## Notes and Caveats

You should be wary about inferring too much from the output of these scripts, for a number of reasons:

* The HTTP Archive, while a fantastic resource, is not representative of the whole Web:
  * They scrape only the top n sites
  * They only load the homepage, without being logged into the site (where applicable)
  * Its data is gathered with a single browser, not diverse clients
  * It is just one point in time
* Furthermore, what's logged in the archive might not be what's seen "on the wire" byte-for-byte, since browsers can and do modify this information before making it available 
* The "other" headers are sometimes not reconstructed accurately (as explained above)
* Headers longer than 254 characters are potentially truncated, so these scripts skip them
* Non-final responses and trailers are not captured
* The parsed data is the result of running a Structured Fields parser; when used on headers that aren't defined as Structured Fields, even when the syntax is compatible, some failures will be in error.