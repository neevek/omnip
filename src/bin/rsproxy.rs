use anyhow::Result;
use clap::Parser;
use rsproxy::*;

extern crate pretty_env_logger;

fn main() -> Result<()> {
    let args = RsproxyArgs::parse();

    rs_utilities::LogHelper::init_logger("rsp", &args.loglevel);

    let config = create_config(
        args.addr,
        args.downstream,
        args.dot_server,
        args.name_servers,
        args.proxy_rules_file,
        args.threads,
        args.watch_proxy_rules_change,
    )?;

    let common_quic_config = CommonQuicConfig {
        cert: args.cert,
        key: args.key,
        password: args.password,
        cipher: args.cipher,
        max_idle_timeout_ms: args.max_idle_timeout_ms,
    };

    let mut server = Server::new(config, common_quic_config);
    server.run()
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RsproxyArgs {
    /// Server address [<http|socks5|socks4|http+quic|socks5+quic|socks4+quic>://][ip:]port
    /// for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[clap(short = 'a', long, required = true, display_order = 1)]
    addr: String,

    /// downstream which the proxy server will relay traffic to based on proxy rules, [<http|socks5|socks4>://]ip:port
    /// for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[clap(short = 'd', long, default_value = "", display_order = 2)]
    downstream: String,

    /// Path to the proxy rules file
    #[clap(short = 'r', long, default_value = "", display_order = 3)]
    proxy_rules_file: String,

    /// Threads to run async tasks, default to number of cpu cores
    #[clap(short = 't', long, default_value = "0", display_order = 4)]
    threads: usize,

    /// DoT (DNS-over-TLS) server, e.g. dns.google
    #[clap(long, default_value = "", display_order = 5)]
    dot_server: String,

    /// comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used if no dot_server is specified, or system default if empty
    #[clap(long, default_value = "", display_order = 6)]
    name_servers: String,

    /// Applicable only for +quic protocols
    /// Path to the certificate file in DER format, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[clap(short = 'c', long, default_value = "", display_order = 7)]
    cert: String,

    /// Applicable only for +quic protocols
    /// Path to the key file in DER format, can be empty if no cert is provided
    #[clap(short = 'k', long, default_value = "", display_order = 8)]
    key: String,

    /// Applicable only for +quic protocols
    /// Password of the +quic server
    #[clap(short = 'p', long, default_value = "", display_order = 9)]
    password: String,

    /// Applicable only for +quic protocols
    /// Password of the +quic server
    #[clap(short = 'e', long, default_value = rstun::SUPPORTED_CIPHER_SUITES[0], display_order = 10, possible_values = rstun::SUPPORTED_CIPHER_SUITES)]
    cipher: String,

    /// Applicable only for quic protocol as downstream
    /// Max idle timeout for the QUIC connections
    #[clap(short = 'i', long, default_value = "120000", display_order = 11)]
    max_idle_timeout_ms: u64,

    /// reload proxy rules if updated
    #[clap(short = 'w', long, action, display_order = 12)]
    watch_proxy_rules_change: bool,

    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 13)]
    loglevel: String,
}
