use clap::Parser;
use log::error;
use rsproxy::*;

extern crate pretty_env_logger;

fn main() {
    let args = RsproxyArgs::parse();

    rs_utilities::LogHelper::init_logger("rsp", &args.loglevel);

    let (server_type, server_addr) = parse_server_addr(args.addr.as_str());
    if !args.addr.is_empty() && server_type.is_none() {
        error!("invalid server address: {}", args.addr);
        return;
    }

    let (downstream_type, downstream_addr) = parse_server_addr(args.downstream.as_str());
    if !args.downstream.is_empty() && downstream_type.is_none() {
        error!("invalid downstream address: {}", args.downstream);
        return;
    }

    let config = Config {
        server_type: server_type.unwrap(),
        addr: server_addr.unwrap(),
        downstream_type,
        downstream_addr,
        proxy_rules_file: args.proxy_rules_file,
        threads: args.threads,
        dot_server: args.dot_server,
        name_servers: args.name_servers,
        watch_proxy_rules_change: args.watch_proxy_rules_change,
    };

    let mut server = Server::new(config);
    // server.set_enable_on_info_report(true);
    // server.set_on_info_listener(|data: &str| {
    //     log::info!("Server Info: {}", data);
    // });
    server.start_and_block().ok();
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct RsproxyArgs {
    /// Server address [<http|socks|socks5|socks4>://][ip:]port, for example: http://127.0.0.1:8000
    #[clap(short = 'a', long, required = true, display_order = 1)]
    addr: String,

    /// downstream which the proxy server will relay traffic to based on proxy rules, http://ip:port | socks5://ip:port | socks4://ip:port
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

    /// reload proxy rules if updated
    #[clap(short = 'w', long, action, display_order = 7)]
    watch_proxy_rules_change: bool,

    #[clap(short = 'l', long, possible_values = &["T", "D", "I", "W", "E"], default_value = "I", display_order = 8)]
    loglevel: String,
}
