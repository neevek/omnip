use clap::Parser;
use log::error;
use rsproxy::*;

extern crate pretty_env_logger;

fn main() {
    let args = RsproxyArgs::parse();

    rs_utilities::LogHelper::init_logger("rsp", &args.loglevel);

    let (server_type, layered_server_type, orig_server_addr) =
        parse_server_addr(args.addr.as_str());

    let orig_server_addr = match match orig_server_addr {
        Some(ref server_addr) => server_addr.to_socket_addr(),
        None => None,
    } {
        Some(server_addr) => server_addr,
        None => {
            error!("server addr must be an IP address: {:?}", args.addr);
            return;
        }
    };

    let (downstream_type, layered_downstream_type, downstream_addr) =
        parse_server_addr(args.downstream.as_str());
    if !args.downstream.is_empty() && downstream_type.is_none() {
        error!("invalid downstream address: {}", args.downstream);
        return;
    }

    let (server_type, server_addr) = match layered_server_type {
        // use random port for the proxy server, the specified port will be used for the tunnel server
        Some(ref layered_type) => (
            layered_type.get_basic_type(),
            local_ipv4_socket_addr_with_unspecified_port(),
        ),
        None => (server_type.unwrap(), orig_server_addr),
    };

    if layered_server_type.is_some() && layered_downstream_type.is_some() {
        error!(
            "QUIC server and QUIC downstream cannot be chained: {} -> {:?}",
            server_addr, downstream_addr
        );
        return;
    }

    let worker_threads = if args.threads > 0 {
        args.threads
    } else {
        num_cpus::get()
    };

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            let require_quic_server = layered_server_type.is_some();
            let require_quic_client = layered_downstream_type.is_some();

            let mut quic_client = None;
            if require_quic_client {
                let quic_client_config = QuicClientConfig {
                    server_addr: downstream_addr.as_ref().unwrap().to_string(),
                    local_access_server_addr: local_ipv4_socket_addr_with_unspecified_port(),
                    cert: args.cert.clone(),
                    key: args.key.clone(),
                    password: args.password.clone(),
                    cipher: args.cipher,
                    max_idle_timeout_ms: args.max_idle_timeout_ms,
                };
                let mut client = QuicClient::new(quic_client_config);
                client.start_access_server().await?;
                quic_client = Some(client);
            }

            let config = Config {
                server_type,
                addr: server_addr,
                downstream_type,
                downstream_addr: match quic_client {
                    // use access server of the tunnel client as downstream if it exists to build proxy chain
                    Some(ref qc) => qc.access_server_addr(),
                    _ => downstream_addr.unwrap().to_socket_addr(),
                },
                proxy_rules_file: args.proxy_rules_file,
                threads: args.threads,
                dot_server: args.dot_server,
                name_servers: args.name_servers,
                watch_proxy_rules_change: args.watch_proxy_rules_change,
            };

            let mut proxy_server = Server::new(config);
            #[cfg(target_os = "android")]
            {
                proxy_server.set_enable_on_info_report(true);
                proxy_server.set_on_info_listener(|data: &str| {
                    log::info!("Server Info: {}", data);
                });
            }

            let proxy_addr = proxy_server.bind().await?;

            if require_quic_server || require_quic_client {
                proxy_server.serve_async().await;

                if let Some(mut qc) = quic_client {
                    qc.connect_and_serve().await;
                }

                if require_quic_server {
                    let quic_server_config = QuicServerConfig {
                        server_addr: orig_server_addr,
                        downstream_addr: proxy_addr,
                        cert: args.cert,
                        key: args.key,
                        password: args.password,
                        max_idle_timeout_ms: args.max_idle_timeout_ms,
                    };
                    let mut quic_server = QuicServer::new(quic_server_config);
                    quic_server.bind().await?;
                    quic_server.serve().await;
                }
            } else {
                proxy_server.serve().await;
            }

            Ok::<(), anyhow::Error>(())
        })
        .ok();
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

// impl RsproxyArgs {
//     fn check_args(&self) {}
// }
