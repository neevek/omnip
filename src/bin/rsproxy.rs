use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use log::{error, info};
use rsproxy::*;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::usize;
use std::{io::Write, sync::RwLock};

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    let args = RsproxyArgs::parse();
    LogHelper::init_logger(args.loglevel.as_ref());

    let addr = parse_sock_addr(&args.addr);
    if addr.is_none() {
        error!("invalid address: {}", args.addr);
        return;
    }

    if !args.proxy_rules_file.is_empty() {
        if !Path::new(&args.proxy_rules_file).is_file() {
            error!("proxy rules file does not exist: {}", args.proxy_rules_file);
            return;
        }
    }

    let config = Config {
        addr: addr.unwrap(),
        downstream_addr: parse_sock_addr(args.downstream.as_str()),
        proxy_rules_file: args.proxy_rules_file,
    };

    if let Some(addr) = config.downstream_addr {
        info!("using downstream: {}", addr);
    }

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let worker_threads = if args.threads > 0 {
        args.threads
    } else {
        num_cpus::get()
    };
    info!("will use {} worker threads", worker_threads);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            run(config).await.unwrap();
        });
}

async fn run(config: Config) -> Result<()> {
    let mut proxy_rule_manager = None;
    if !config.proxy_rules_file.is_empty() {
        let mut prm = ProxyRuleManager::new();
        let count = prm.add_rules_by_file(config.proxy_rules_file.as_str());
        proxy_rule_manager = Some(Arc::new(RwLock::new(prm)));

        info!(
            "{} proxy rules added with file: {}",
            count, config.proxy_rules_file
        );
    }

    let mut server = Server::new(config.addr, config.downstream_addr, proxy_rule_manager);
    server.bind().await?;
    server.start().await?;
    Ok(())
}

fn parse_sock_addr(addr: &str) -> Option<SocketAddr> {
    let mut addr = addr.to_string();
    let mut start_pos = 0;
    if let Some(ipv6_end_bracket_pos) = addr.find("]") {
        start_pos = ipv6_end_bracket_pos + 1;
    }
    if addr[start_pos..].find(":").is_none() {
        addr = format!("127.0.0.1:{}", addr);
    }
    Some(addr.parse().ok()?)
}

pub struct LogHelper {}
impl LogHelper {
    pub fn init_logger(loglevel_filter_str: &str) {
        let loglevel_filter;
        match loglevel_filter_str.as_ref() {
            "D" => loglevel_filter = log::LevelFilter::Debug,
            "I" => loglevel_filter = log::LevelFilter::Info,
            "W" => loglevel_filter = log::LevelFilter::Warn,
            "E" => loglevel_filter = log::LevelFilter::Error,
            _ => loglevel_filter = log::LevelFilter::Trace,
        }

        pretty_env_logger::formatted_timed_builder()
            .format(|buf, record| {
                let level = record.level();
                let level = match level {
                    log::Level::Trace => "T".white(),
                    log::Level::Debug => "D".green(),
                    log::Level::Info => "I".blue(),
                    log::Level::Warn => "W".yellow(),
                    log::Level::Error => "E".red(),
                };
                let filename = record.file().unwrap_or("unknown");
                let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
                writeln!(
                    buf,
                    "{} [{}:{}] [{}] - {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
                    filename,
                    record.line().unwrap_or(0),
                    level,
                    record.args()
                )
            })
            .filter(Some("rsproxy"), loglevel_filter)
            .init();
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RsproxyArgs {
    /// Address ([ip:]port pair) to listen on
    #[clap(short = 'l', long, required = true, display_order = 1)]
    addr: String,

    /// Downstream of current proxy server, e.g. -d [ip:]port
    #[clap(short = 'd', long, default_value = "", display_order = 2)]
    downstream: String,

    /// Path to the proxy rules file
    #[clap(short = 'r', long, default_value = "", display_order = 3)]
    proxy_rules_file: String,

    /// Threads to run async tasks
    #[clap(short = 't', long, default_value = "0", display_order = 3)]
    threads: usize,

    #[clap(short = 'L', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 4)]
    loglevel: String,
}
