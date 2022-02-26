rsproxy
=======

An HTTP proxy written in Rust.


Features
--------

1. basic HTTP/HTTPS proxy
2. proxy chaining with the `--downstream` option. E.g. `--downstream PORT` to forwarrd connections to the specified PORT
3. proxy rules support, this works when a downstream and a proxy rule file is specified


```
rsproxy 0.1.3

USAGE:
    rsproxy [OPTIONS] --addr <ADDR>

OPTIONS:
    -l, --addr <ADDR>
            Address ([ip:]port pair) to listen on

    -d, --downstream <DOWNSTREAM>
            Downstream of current proxy server, e.g. -d [ip:]port [default: ]

    -r, --proxy-rules-file <PROXY_RULES_FILE>
            Path to the proxy rules file [default: ]

    -t, --threads <THREADS>
            Threads to run async tasks [default: 0]

    -L, --loglevel <LOGLEVEL>
            [default: I] [possible values: T, D, I, W, E]

    -h, --help
            Print help information

    -V, --version
            Print version information
```

License
-------
Later...
