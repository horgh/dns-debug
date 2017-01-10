These are tools to aid in debugging the behaviour of a DNS server. Specifically,
they provide a way to craft DNS questions, and examine the responses from a DNS
server. I do this without using any DNS library as I want to see at a low level
of detail.

Background: I have a DNS server on an embedded device that exhibits problematic
behaviour. I am attempting to understand what is happening. To do that I wanted
to be able to be able to capture and dump the DNS messages it is sending back
and look at each field in detail.

There are currently two programs:

  * dns-debug creates an IN A question message and sends it to a DNS server via
    TCP. It parses the resulting answer and outputs everything inside it. It
    also has the ability to save the answer in its raw form to a file for later
    analysis. I will use this to continuously query my problem DNS server with
    the hope that I will catch it misbehaving.
  * dns-read-messages reads the file containing raw DNS messages written by
    dns-debug. It is for post-capture analysis.

I wrote these in Ruby for practice with that language.


## My DNS server problem
I have a program called
[cfiupdate](https://github.com/horgh/cloudflare/tree/master/cfipupdate) which I
use to keep a hostname updated on a server with a dynamic IP. Periodically I
see it spitting out DNS errors which I think should not be happening given its
server is the router on the local LAN, a [MikroTik hAP
ac](https://routerboard.com/RB962UiGS-5HacT2HnT).

Examples of the errors:

`Unable to perform lookup: read udp 192.168.0.201:37461->192.168.0.200:53: i/o timeout`

`Unable to look up IP from icanhazip.com: Request problem: Get https://icanhazip.com: dial tcp: lookup icanhazip.com on 192.168.0.200:53: server misbehaving`

The second is the one I am most interested in, though of course the first is
also odd.

This program uses the built in Go DNS library. After looking at its code where
the 'server misbehaving' message originates, I see it happens when the DNS RCODE
is something other than 0 (no error) or 3 (NXDOMAIN). I want to see exactly what
the server is saying.
