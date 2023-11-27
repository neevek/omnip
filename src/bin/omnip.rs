use anyhow::Result;
use clap::builder::TypedValueParser as _;
use clap::{builder::PossibleValuesParser, Parser};
use omnip::*;

extern crate pretty_env_logger;

fn main() -> Result<()> {
    let args = OmnipArgs::parse();
    let log_filter = format!(
        "omnip={},rstun={},rs_utilities={}",
        args.loglevel, args.loglevel, args.loglevel
    );
    rs_utilities::LogHelper::init_logger("omnip", log_filter.as_str());

    let config = create_config(
        args.addr,
        args.upstream,
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
        retry_interval_ms: args.retry_interval_ms,
        threads: args.threads,
    };

    let mut server = Server::new(config, common_quic_config);
    server.run()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct OmnipArgs {
    /// Server address [<tcp|http|socks5|socks4|tcp+quic|http+quic|socks5+quic|socks4+quic>://][ip:]port
    /// for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[arg(short = 'a', long, required = true)]
    addr: String,

    /// upstream which the proxy server will relay traffic to based on proxy rules, [<http|socks5|socks4>://]ip:port
    /// for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[arg(short = 'u', long, default_value = "")]
    upstream: String,

    /// Path to the proxy rules file
    #[arg(short = 'r', long, default_value = "")]
    proxy_rules_file: String,

    /// Threads to run async tasks, default to number of cpu cores
    #[arg(short = 't', long, default_value = "0")]
    threads: usize,

    /// DoT (DNS-over-TLS) server, e.g. dns.google
    #[arg(long, default_value = "")]
    dot_server: String,

    /// comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used if no dot_server is specified, or system default if empty
    #[arg(long, default_value = "")]
    name_servers: String,

    /// Applicable only for +quic protocols
    /// Path to the certificate file, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[arg(short = 'c', long, default_value = "")]
    cert: String,

    /// Applicable only for +quic protocols
    /// Path to the key file, can be empty if no cert is provided
    #[arg(short = 'k', long, default_value = "")]
    key: String,

    /// Applicable only for +quic protocols
    /// Password of the +quic server
    #[arg(short = 'p', long, default_value = "")]
    password: String,

    /// Applicable only for +quic protocols
    /// Password of the +quic server
    #[arg(short = 'e', long, default_value_t = String::from(rstun::SUPPORTED_CIPHER_SUITES[0]),
        value_parser = PossibleValuesParser::new(rstun::SUPPORTED_CIPHER_SUITES).map(|v| v.to_string()))]
    cipher: String,

    /// Applicable only for quic protocol as upstream
    /// Max idle timeout for the QUIC connections
    #[arg(short = 'i', long, default_value = "120000")]
    max_idle_timeout_ms: u64,

    /// Applicable only for quic protocol as upstream
    /// Max idle timeout for the QUIC connections
    #[arg(short = 'R', long, default_value = "5000")]
    retry_interval_ms: u64,

    /// reload proxy rules if updated
    #[arg(short = 'w', long, action)]
    watch_proxy_rules_change: bool,

    /// Log level
    #[arg(short = 'l', long, default_value_t = String::from("I"),
        value_parser = PossibleValuesParser::new(["T", "D", "I", "W", "E"]).map(|v| match v.as_str() {
            "T" => "trace",
            "D" => "debug",
            "I" => "info",
            "W" => "warn",
            "E" => "error",
            _ => "info",
        }.to_string()))]
    loglevel: String,
}
