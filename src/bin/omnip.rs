use anyhow::{bail, Context, Result};
use base64::prelude::*;
use byte_pool::BytePool;
use clap::builder::TypedValueParser as _;
use clap::{builder::PossibleValuesParser, Parser};
use dashmap::DashMap;
use omnip::*;
use rs_utilities::log_and_bail;
use rstun::{StreamRequest, UdpMessage, UdpPacket, UDP_PACKET_SIZE};
use std::borrow::BorrowMut;
use std::env;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use url::Url;

extern crate pretty_env_logger;

use etherparse::Icmpv4Header;
use ipstack::{IpNumber, IpStackStream, IpStackUdpStream};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{io::AsyncWriteExt, net::TcpStream};

use lazy_static::lazy_static;
use udp_stream::UdpStream;

lazy_static! {
    static ref BUFFER_POOL: BytePool::<Vec<u8>> = BytePool::<Vec<u8>>::new();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_filter = format!("omnip=debug,rstun=debug,rs_utilities=debug");
    rs_utilities::LogHelper::init_logger("omnip", log_filter.as_str());

    const MTU: u16 = 1500;
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 5);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut config = tun::Configuration::default();
    config
        .address(ipv4)
        .destination(dst)
        .netmask(netmask)
        .mtu(MTU)
        .up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(12324323423423434234_u128);
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU);
    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun::create_as_async(&config)?);

    let common_quic_config = CommonQuicConfig {
        cert: "".to_string(),
        key: "".to_string(),
        password: "123".to_string(),
        cipher: "".to_string(),
        quic_timeout_ms: 10000,
        retry_interval_ms: 10000,
        workers: 2,
        tcp_timeout_ms: 10000,
        udp_timeout_ms: 10000,
    };

    let quic_client_config = QuicClientConfig {
        server_addr: "192.168.50.5:9999".parse().unwrap(),
        local_tcp_server_addr: None,
        local_udp_server_addr: None,
        common_cfg: common_quic_config,
        dot_servers: vec![],
        name_servers: vec![],
    };

    let mut client = QuicClient::new(quic_client_config);

    let (tcp_sender, tcp_reciever) = channel(3);
    client.connect_and_serve_tcp_async(tcp_reciever);

    let udp_map: DashMap<SocketAddr, Arc<Mutex<IpStackUdpStream>>> = DashMap::new();
    let (in_udp_sender, mut in_udp_receiver) = channel(3);
    let (out_udp_sender, out_udp_receiver) = channel(3);
    client.connect_and_serve_udp_async((in_udp_sender, out_udp_receiver));

    let m = udp_map.clone();
    tokio::spawn(async move {
        loop {
            match in_udp_receiver.recv().await {
                Some(UdpMessage::Packet(p)) => {
                    let m = m.clone();
                    let udp = m.remove(&p.local_addr);
                    if let Some(udp) = udp {
                        udp.1.lock().await.write_all(&p.payload).await.ok();
                        // udp_map.insert(p.local_addr, udp.1);
                    }
                }
                Some(UdpMessage::Quit) => {
                    log::info!("udp server is requested to quit");
                    break;
                }
                None => {
                    // all senders quit
                    log::info!("udp server quit");
                    break;
                }
            }
        }
    });

    log::info!(">>>>>> haha start");

    while let Ok(stream) = ip_stack.accept().await {
        match stream {
            IpStackStream::Tcp(tcp) => {
                // log::info!(
                //     ">>>>>> new request:{} -> {}",
                //     tcp.local_addr(),
                //     tcp.peer_addr()
                // );
                tcp_sender
                    .send(rstun::StreamMessage::Request(StreamRequest {
                        dst_addr: Some(tcp.peer_addr()),
                        stream: RstunAsyncStream(tcp),
                    }))
                    .await
                    .unwrap();
                // let mut rhs = TcpStream::connect("1.1.1.1:80").await?;
                // tokio::spawn(async move {
                //     let _ = tokio::io::copy_bidirectional(&mut tcp, &mut rhs).await;
                //     let _ = rhs.shutdown().await;
                //     let _ = tcp.shutdown().await;
                // });
            }
            IpStackStream::Udp(mut udp) => {
                log::info!(">>>>>>>> udp: {} -> {}", udp.local_addr(), udp.peer_addr());
                let mut payload = BUFFER_POOL.alloc_and_fill(UDP_PACKET_SIZE);
                if let Ok(size) = udp.read(&mut payload).await {
                    if size > 0 {
                        let udp_packet = UdpPacket {
                            payload,
                            local_addr: udp.local_addr(),
                            peer_addr: Some(udp.peer_addr()),
                        };
                        out_udp_sender
                            .send(rstun::UdpMessage::Packet(udp_packet))
                            .await
                            .ok();
                        udp_map.insert(udp.local_addr(), Arc::new(Mutex::new(udp)));
                    }
                }

                // let addr: SocketAddr = "1.1.1.1:53".parse()?;
                // let mut rhs = UdpStream::connect(addr).await?;
                // tokio::spawn(async move {
                //     let _ = tokio::io::copy_bidirectional(&mut udp, &mut rhs).await;
                //     rhs.shutdown();
                //     let _ = udp.shutdown().await;
                // });
            }
            IpStackStream::UnknownTransport(u) => {
                if u.src_addr().is_ipv4() && u.ip_protocol() == IpNumber::ICMP {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(echo) = icmp_header.icmp_type {
                        println!("ICMPv4 echo");
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload)?;
                    } else {
                        println!("ICMPv4");
                    }
                    continue;
                }
                println!("unknown transport - Ip Protocol {:?}", u.ip_protocol());
            }
            IpStackStream::UnknownNetwork(pkt) => {
                println!("unknown transport - {} bytes", pkt.len());
            }
        }
    }
    Ok(())
}

fn main2() -> Result<()> {
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
        args.tcp_timeout_ms,
        args.udp_timeout_ms,
    )?;

    let common_quic_config = CommonQuicConfig {
        cert: args.cert,
        key: args.key,
        password: args.password,
        cipher: args.cipher,
        quic_timeout_ms: args.quic_timeout_ms,
        tcp_timeout_ms: args.tcp_timeout_ms,
        udp_timeout_ms: args.udp_timeout_ms,
        retry_interval_ms: args.retry_interval_ms,
        workers: args.threads,
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
    #[arg(short = 'a', long, verbatim_doc_comment, required = true)]
    addr: String,

    /// Upstream which the proxy server will relay traffic to based on proxy rules,
    /// [<http|socks5|socks4>://]ip:port for example: http://127.0.0.1:8000, http+quic://127.0.0.1:8000
    #[arg(short = 'u', long, verbatim_doc_comment, default_value = "")]
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
    #[arg(long, verbatim_doc_comment, default_value = "")]
    name_servers: String,

    /// Applicable only for +quic protocols
    /// Path to the certificate file, if empty, a self-signed certificate
    /// with the domain "localhost" will be used
    #[arg(short = 'c', long, verbatim_doc_comment, default_value = "")]
    cert: String,

    /// Applicable only for +quic protocols
    /// Path to the key file, can be empty if no cert is provided
    #[arg(short = 'k', long, verbatim_doc_comment, default_value = "")]
    key: String,

    /// Applicable only for +quic protocols
    /// Password of the +quic server
    #[arg(short = 'p', long, verbatim_doc_comment, default_value = "")]
    password: String,

    /// Applicable only for +quic protocols
    /// Cipher for encryption
    #[arg(short = 'e', long, verbatim_doc_comment, default_value_t = String::from(rstun::SUPPORTED_CIPHER_SUITE_STRS[0]),
        value_parser = PossibleValuesParser::new(rstun::SUPPORTED_CIPHER_SUITE_STRS).map(|v| v.to_string()))]
    cipher: String,

    /// Applicable only for quic protocol as upstream
    /// Max idle timeout for the QUIC connections
    #[arg(short = 'i', long, verbatim_doc_comment, default_value = "120000")]
    quic_timeout_ms: u64,

    /// Read timeout in milliseconds for TCP connections
    #[arg(long, verbatim_doc_comment, default_value = "30000")]
    tcp_timeout_ms: u64,

    /// Read timeout in milliseconds for UDP connections
    #[arg(long, verbatim_doc_comment, default_value = "5000")]
    udp_timeout_ms: u64,

    /// Applicable only for quic protocol as upstream
    /// Max idle timeout for the QUIC connections
    #[arg(short = 'R', long, verbatim_doc_comment, default_value = "5000")]
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
    #[arg(short = 'E', long, verbatim_doc_comment, action)]
    encode_base64: bool,

    /// Decode and print the base64 encoded opp:// address
    #[arg(short = 'D', long, action)]
    decode_base64: bool,
}
