use anyhow::{bail, Context, Result};
use base64::prelude::*;
use clap::builder::TypedValueParser as _;
use clap::{builder::PossibleValuesParser, Parser};
use log::error;
use omnip::*;
use rs_utilities::log_and_bail;
use std::env;
use url::Url;

extern crate pretty_env_logger;

fn main() -> Result<()> {
    let args = parse_args()?;
    if args.decode_base64 || print_args_as_base64(&args) {
        return Ok(());
    }

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
        args.tcp_nodelay,
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

fn parse_args() -> Result<OmnipArgs> {
    let args = OmnipArgs::parse();
    if args.addr.starts_with("opp://") {
        match Url::parse(args.addr.as_str()) {
            Ok(url) => {
                let base64_args = url.host().context("invalid opp args")?.to_string();
                let space_sep_args = String::from_utf8(
                    BASE64_STANDARD
                        .decode(base64_args)
                        .context("invalid base64")?,
                )?;
                if args.decode_base64 {
                    println!("{space_sep_args}");
                    // simply print the args and quit
                    return Ok(args);
                }

                let parts: Vec<String> = space_sep_args
                    .split_whitespace()
                    .map(String::from)
                    .collect();
                let mut vec_args = vec![String::from("")]; // empty string as the first arg (the programm name)
                vec_args.extend(parts);

                return Ok(OmnipArgs::parse_from(vec_args));
            }
            _ => {
                log_and_bail!("invalid addr: {}", args.addr);
            }
        };
    }
    Ok(args)
}

fn print_args_as_base64(args: &OmnipArgs) -> bool {
    if args.encode_base64 {
        let space_sep_args = env::args_os()
            .skip(1)
            .filter(|arg| arg != "-E" && arg != "--encode-base64")
            .map(|arg| {
                arg.into_string()
                    .unwrap_or_else(|os_str| os_str.to_string_lossy().into_owned())
            })
            .collect::<Vec<String>>()
            .join(" ");

        let base64_args = BASE64_STANDARD.encode(space_sep_args.as_bytes());
        println!("opp://{base64_args}");
        true
    } else {
        false
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct OmnipArgs {
    /// Server address [<tcp|http|socks5|socks4|tcp+quic|http+quic|socks5+quic|socks4+quic>://][ip:]port
    /// for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[arg(short = 'a', long, required = true)]
    addr: String,

    /// upstream which the proxy server will relay traffic to based on proxy rules,
    /// [<http|socks5|socks4>://]ip:port for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
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

    /// comma saprated domain servers (E.g. 1.1.1.1,8.8.8.8), which will be used
    /// if no dot_server is specified, or system default if empty
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

    /// Set TCP_NODELAY
    #[arg(long, action)]
    tcp_nodelay: bool,

    /// Reload proxy rules if updated
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

    /// Print the args as base64 string to be used in opp:// address, will be ignored if passing in
    /// as an opp:// address, which can combine all args as a single base64 string
    #[arg(short = 'E', long, action)]
    encode_base64: bool,

    /// Decode and print the base64 encoded opp:// address
    #[arg(short = 'D', long, action)]
    decode_base64: bool,
}
