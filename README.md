rsproxy
=======

HTTP and SOCKS proxy written in Rust.

Features
--------

1. Supports [HTTP tunneling](https://en.wikipedia.org/wiki/HTTP_tunnel) and basic HTTP proxy.
2. Supports `CONNECT` command of both [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928) and [SOCKS4](https://www.openssh.com/txt/socks4.protocol) with [SOCKS4a](https://www.openssh.com/txt/socks4a.protocol) extension. In the case of being a node in a proxy chain, the implementation always delays DNS resolution to the next node, only when acting as the last node will it resolves DNS.
2. Proxy chaining with the `--downstream` option. e.g. `--downstream http://ip:port` or `--downstream socks5://ip:port` to forward payload to another http proxy or SOCKS proxy.
3. Supports simple proxy rules, traffic will be relayed to downstream if the requested domain matches one of the proxy rules, for example:
    * example.com
    * .example.com
    * ||example.com
    * ...
4. DoT (DNS-over-TLS) or custom name servers are supported.
5. JNI interface provided for Androd (Java/Kotlin), see [lib.rs](https://github.com/neevek/rsproxy/blob/master/src/lib.rs).


```
rsproxy 0.3.0

USAGE:
    rsproxy [OPTIONS] --addr <ADDR>

OPTIONS:
    -a, --addr <ADDR>
            Server address [<http|socks5|socks4>://][ip:]port, for example: http://127.0.0.1:8000

    -d, --downstream <DOWNSTREAM>
            downstream which the proxy server will relay traffic to based on proxy rules,
            [<http|socks5|socks4>://]ip:port [default: ]

    -r, --proxy-rules-file <PROXY_RULES_FILE>
            Path to the proxy rules file [default: ]

    -t, --threads <THREADS>
            Threads to run async tasks, default to number of cpu cores [default: 0]

        --dot-server <DOT_SERVER>
            DoT (DNS-over-TLS) server, e.g. dns.google [default: ]

        --name-servers <NAME_SERVERS>
            comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used if no
            dot_server is specified, or system default if empty [default: ]

    -w, --watch-proxy-rules-change
            reload proxy rules if updated

    -l, --loglevel <LOGLEVEL>
            [default: I] [possible values: T, D, I, W, E]

    -h, --help
            Print help information

    -V, --version
            Print version information
```

License
-------

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
