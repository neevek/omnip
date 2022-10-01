rsproxy
=======

An HTTP proxy written in Rust.


Features
--------

1. Basic [HTTP tunneling](https://en.wikipedia.org/wiki/HTTP_tunnel).
2. Proxy chaining with the `--downstream` option. e.g. `--downstream PORT` to forward connections to the specified PORT.
3. Simple proxy rules support, traffic will be relayed to downstream if the requested domain matches one of the proxy rules, for example:
    * example.com
    * .example.com
    * ||example.com
    * ...
4. DoT (DNS-over-TLS) or custom name servers are supported.
5. JNI interface provided for Androd (Java/Kotlin), simply declare the required native methods in Java/Kotlin (see [lib.rs](https://github.com/neevek/rsproxy/blob/master/src/lib.rs)) and call it.


```
rsproxy 0.1.11

USAGE:
    rsproxy [OPTIONS] --addr <ADDR>

OPTIONS:
    -l, --addr <ADDR>
            Address ([ip:]port pair) to listen on

    -d, --downstream <DOWNSTREAM>
            [ip:]port, downstream which the proxy server will relay traffic to based on proxy rules
            [default: ]

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

    -L, --loglevel <LOGLEVEL>
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
