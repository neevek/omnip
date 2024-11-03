omnip - [tcp | udp | http proxy | socks proxy] over quic
--------

An all-in-one proxy written in Rust.

Features
--------

1. Supports [HTTP tunneling](https://en.wikipedia.org/wiki/HTTP_tunnel) and basic HTTP proxy.
2. Supports `CONNECT` command of both [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928) and [SOCKS4](https://www.openssh.com/txt/socks4.protocol) with [SOCKS4a](https://www.openssh.com/txt/socks4a.protocol) extension. In the case of being a node in a proxy chain, the implementation always delays DNS resolution to the next node, only when acting as the last node will it resolve DNS.
3. Proxy chaining with the `--upstream` option. e.g. `--upstream http://ip:port` or `--upstream socks5://ip:port` to forward payload to another HTTP proxy or SOCKS proxy.
4. Proxy over [QUIC](https://quicwg.org/), i.e. `http+quic`, `socks5+quic` and `socks4+quic`, for example:
    * Start a QUIC server backed by an HTTP proxy on a remote server (HTTP proxy over QUIC):
      * `omnip -a http+quic://0.0.0.0:3515 -lD`
    * Start a local SOCKS5 proxy and forward all its payload to the HTTP proxy server through QUIC tunnel (everything is encrypted):
      * `omnip -a socks5://127.0.0.1:9000 --upstream http+quic://DOMAIN:3515 -lD`
    Note: The commands above will use auto-generated self-signed certificate for QUIC, which is for demonstration only. Domain name with certificate issued by trusted CA is recommended. For more details, see README of the [rstun](https://github.com/neevek/rstun) project, which omnip uses to implement proxy over QUIC. And remember to set a password for the server with the `-p` or `--password` option.
5. Supports plain tcp connections over QUIC, which can be used to expose a port of remote server through the QUIC tunnel, for example:
    * Start a QUIC server that forwards all its tcp payload to the local SSH port:
      * `omnip -a tcp+quic://0.0.0.0:3515 --upstream tcp://127.0.0.1:22 -lD`
    * Connect to the tunnel server and SSH into the remote server through the QUIC tunnel:
      * `omnip -a tcp://0.0.0.0:3721 --upstream tcp+quic://DOMAIN:3515 -lD`
      * `ssh -p 3721 user@127.0.0.1`
6. Supports plain udp tunneling over QUIC, for example:
    * Start a QUIC server that forwards all its udp payload to `1.1.1.1:53`:
      * `omnip -a udp+quic://0.0.0.0:3515 --upstream udp://1.1.1.1:53 -lD`
    * Connect to the tunnel server and resolve DNS via the tunnel:
      * `omnip -a udp://0.0.0.0:5353 --upstream udp+quic://DOMAIN:3515 -lD`
      * `dig @127.0.0.1 -p 5353 github.com`
7. Supports simple proxy rules, traffic will be relayed to upstream if the requested domain matches one of the proxy rules, this is for achieving *Smart Proxy* to control which domains should be forwarded through the tunnel, for example:
    * example.com
    * .example.com
    * ||example.com
    * ...
8. Supports DoT (DNS-over-TLS) or custom name servers, for example: `--dot-server dns.google`, `--name-servers 1.1.1.1,8.8.8.8`, if both are specified, DoT server takes precedence.
9. Simple Web UI can be accessed from the same port of the proxy server, DNS servers and tunnel connection can be configured through the Web UI.

Examples
--------

1. Running omnip in its simplest form:

    ```
    omnip -a 8000
    ```

    omnip is bound to `127.0.0.1:8000`, running as a proxy server that supports HTTP, SOCKS5 and SOCKS4. The complete format for the `-a|--addr` option is `scheme://[ip|domain]:port`, so the following command is allowed, but it will be restricted to supporting SOCKS5 only, and the proxy server will be listening on all available network interfaces on the machine:

    ```
    omnip -a socks5://0.0.0.0:8000
    ```

2. Chaining proxy servers:

    `omnip -a socks5://127.0.0.1:8000 -u http://192.168.50.50:9000`

    omnip runs as a SOCKS5 proxy server, which forwards all the proxy requests to the upstream server specified with the `-u|--upstream` option, in this case it simply translates SOCKS5 proxy requests to HTTP proxy requests. the schemes of the upstream can be one of `http`, `socks5`, `socks4` and their QUIC counterparts `http+quic`, `socks5+quic` and `socks4+quic`.

3. Running omnip as QUIC secured proxy server:

    `omnip -a socks5+quic://0.0.0.0:8000 -p passward123`

    omnip runs as a QUIC secured proxy server, which is supposed to be used as an *upstream* by a normal proxy server through chaining, see above. In this case a temporary self-signed certificate is generated for the server and the server name of the certificate is always set to `localhost`, note this is for demo only.

4. Running omnip as QUIC secured proxy server, with custom self-signed certificate and its associated private key in PEM format:

    `omnip -a socks5+quic://0.0.0.0:8000 -p passward123 -c CERT_FILE -k KEY_FILE`

    Note: Normal omnip proxy server setting this QUIC server as upstream must provide the same self-signed certificate file.

5. Running omnip as QUIC secured proxy server, with certificate issued by trusted CA:

    `omnip -a socks5+quic://DOMAIN:8000 -p passward123 -c CERT_FILE -k KEY_FILE`

    Note: The server is running with DOMAIN and certificate issued by trusted CA, normal omnip proxy server setting this QUIC server as upstream must use the same DOMAIN, but NO certificate is needed in this case.

6. Chaining omnip proxy servers with QUIC in between:

    `omnip -a 0.0.0.0:9000 -u socks5+quic://DOMAIN:8000 -p passward123`

    Traffic going from `0.0.0.0:9000` to `DOMAIN:8000` will be secured by the QUIC tunnel in this case.

7. Running omnip proxy server with proxy rules:

    `omnip -a 0.0.0.0:9000 -u socks5+quic://DOMAIN:8000 -p passward123 -r PROXY_RULES_FILE`

    PROXY_RULES_FILE is a simple text file in which each line contains a simple rule for a domain.


![omnip](https://github.com/neevek/omnip/raw/master/omnip1.jpg)
![omnip](https://github.com/neevek/omnip/raw/master/omnip2.jpg)

```
Usage: omnip [OPTIONS] --addr <ADDR>

Options:
  -a, --addr <ADDR>
          Server address [<tcp|http|socks5|socks4|tcp+quic|http+quic|socks5+quic|socks4+quic>://][ip:]port
          for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
  -u, --upstream <UPSTREAM>
          Upstream which the proxy server will relay traffic to based on proxy rules,
          [<http|socks5|socks4>://]ip:port for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000 [default: ]
  -r, --proxy-rules-file <PROXY_RULES_FILE>
          Path to the proxy rules file [default: ]
  -t, --threads <THREADS>
          Threads to run async tasks, default to number of cpu cores [default: 0]
      --dot-server <DOT_SERVER>
          DoT (DNS-over-TLS) server, e.g. dns.google [default: ]
      --name-servers <NAME_SERVERS>
          comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used
          if no dot_server is specified, or system default if empty [default: ]
  -c, --cert <CERT>
          Applicable only for +quic protocols
          Path to the certificate file, if empty, a self-signed certificate
          with the domain "localhost" will be used [default: ]
  -k, --key <KEY>
          Applicable only for +quic protocols
          Path to the key file, can be empty if no cert is provided [default: ]
  -p, --password <PASSWORD>
          Applicable only for +quic protocols
          Password of the +quic server [default: ]
  -e, --cipher <CIPHER>
          Applicable only for +quic protocols
          Cipher for encryption [default: chacha20-poly1305] [possible values: chacha20-poly1305, aes-256-gcm, aes-128-gcm]
  -i, --max-idle-timeout-ms <MAX_IDLE_TIMEOUT_MS>
          Applicable only for quic protocol as upstream
          Max idle timeout for the QUIC connections [default: 120000]
  -R, --retry-interval-ms <RETRY_INTERVAL_MS>
          Applicable only for quic protocol as upstream
          Max idle timeout for the QUIC connections [default: 5000]
      --tcp-nodelay
          Set TCP_NODELAY
  -w, --watch-proxy-rules-change
          Reload proxy rules if updated
  -l, --loglevel <LOGLEVEL>
          Log level [default: I] [possible values: T, D, I, W, E]
  -E, --encode-base64
          Print the args as base64 string to be used in opp:// address, will be ignored if passing in
          as an opp:// address, which can combine all args as a single base64 string
  -D, --decode-base64
          Decode and print the base64 encoded opp:// address
  -h, --help
          Print help
  -V, --version
          Print version
```

License
-------

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
