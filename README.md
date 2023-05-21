rsproxy - HTTP / SOCKS over QUIC
=======

An all in one proxy implementation written in Rust.

Features
--------

1. Supports [HTTP tunneling](https://en.wikipedia.org/wiki/HTTP_tunnel) and basic HTTP proxy.
2. Supports `CONNECT` command of both [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928) and [SOCKS4](https://www.openssh.com/txt/socks4.protocol) with [SOCKS4a](https://www.openssh.com/txt/socks4a.protocol) extension. In the case of being a node in a proxy chain, the implementation always delays DNS resolution to the next node, only when acting as the last node will it resolve DNS.
3. Proxy chaining with the `--upstream` option. e.g. `--upstream http://ip:port` or `--upstream socks5://ip:port` to forward payload to another http proxy or SOCKS proxy.
4. Proxy over [QUIC](https://quicwg.org/), i.e. `http+quic`, `socks5+quic` and `socks4+quic`. For example:
    * Start a QUIC server backed by an HTTP proxy on a remote server (HTTP proxy over QUIC):
      * `rsproxy -a http+quic://0.0.0.0:3515`
    * Start a local SOCKS5 proxy and forward all its traffic to the HTTP proxy server through QUIC tunnel (everything is encrypted):
      * `rsproxy -a socks5://127.0.0.1:9000 --upstream http+quic://DOMAIN:3515`

    Note: The commands above will use auto-generated self-signed certificate for QUIC, which is for demonstration only. Domain name with certificate issued by trusted CA are recommended. For more details, see README of the [rstun](https://github.com/neevek/rstun) project, which rsproxy uses to implement proxy over QUIC. And remember to set a password for the server with the `-p` or `--password` option.

5. Supports simple proxy rules, traffic will be relayed to upstream if the requested domain matches one of the proxy rules, this is for achieving *Smart Proxy* to control which domains should be forwarded through the tunnel, for example:
    * example.com
    * .example.com
    * ||example.com
    * ...
6. Supports DoT (DNS-over-TLS) or custom name servers, for example: `--dot-server dns.google`, `--name-servers 1.1.1.1,8.8.8.8`, if both are specified, DoT server takes precedence.
7. Simple Web UI can be accessed from the same port of the proxy server, DNS servers and tunnel connection can be configured through the Web UI.

![rsproxy](https://github.com/neevek/rsproxy/raw/master/rsproxy1.jpg)
![rsproxy](https://github.com/neevek/rsproxy/raw/master/rsproxy2.jpg)

```
USAGE:
    rsproxy [OPTIONS] --addr <ADDR>

OPTIONS:
    -a, --addr <ADDR>
            Server address [<http|socks5|socks4|http+quic|socks5+quic|socks4+quic>://][ip:]port for
            example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000

    -u, --upstream <UPSTREAM>
            upstream which the proxy server will relay traffic to based on proxy rules,
            [<http|socks5|socks4>://]ip:port for example: http://127.0.0.1:8000,
            http+quic://127.0.0.1:8000 [default: ]

    -r, --proxy-rules-file <PROXY_RULES_FILE>
            Path to the proxy rules file [default: ]

    -t, --threads <THREADS>
            Threads to run async tasks, default to number of cpu cores [default: 0]

        --dot-server <DOT_SERVER>
            DoT (DNS-over-TLS) server, e.g. dns.google [default: ]

        --name-servers <NAME_SERVERS>
            comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used if no
            dot_server is specified, or system default if empty [default: ]

    -c, --cert <CERT>
            Applicable only for +quic protocols Path to the certificate file in DER format, if
            empty, a self-signed certificate with the domain "localhost" will be used [default: ]

    -k, --key <KEY>
            Applicable only for +quic protocols Path to the key file in DER format, can be empty if
            no cert is provided [default: ]

    -p, --password <PASSWORD>
            Applicable only for +quic protocols Password of the +quic server [default: ]

    -e, --cipher <CIPHER>
            Applicable only for +quic protocols Password of the +quic server [default:
            chacha20-poly1305] [possible values: chacha20-poly1305, aes-256-gcm, aes-128-gcm]

    -i, --max-idle-timeout-ms <MAX_IDLE_TIMEOUT_MS>
            Applicable only for quic protocol as upstream Max idle timeout for the QUIC
            connections [default: 120000]

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
