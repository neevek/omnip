mod admin;
mod api;
mod http;
mod proxy_handler;
mod proxy_rule_manager;
mod quic;
mod server;
mod server_info_bridge;
mod socks;
mod udp;
mod utils;

use anyhow::Context;
use anyhow::{bail, Result};
pub use api::Api;
use byte_pool::{Block, BytePool};
use lazy_static::lazy_static;
use log::{error, warn};
pub use proxy_rule_manager::ProxyRuleManager;
pub use quic::quic_client::QuicClient;
pub use quic::quic_server::QuicServer;
use rs_utilities::log_and_bail;
use serde::{Deserialize, Serialize};
pub use server::Server;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use url::Url;

const INTERNAL_DOMAIN_SURRFIX: [&str; 6] = [
    ".home",
    ".lan",
    ".corp",
    ".intranet",
    ".private",
    "localhost",
];

lazy_static! {
    static ref BUFFER_POOL: BytePool::<Vec<u8>> = BytePool::<Vec<u8>>::new();
}

type PooledBuffer<'a> = Block<'a>;

#[derive(Debug)]
pub enum ProxyError {
    ConnectionRefused,
    IPv6NotSupported, // not supported by Socks4
    InternalError,
    BadRequest,
    Timeout,
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub enum Host {
    IP(IpAddr),
    Domain(String),
}

impl Display for Host {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::IP(ip) => formatter.write_fmt(format_args!("{}", ip)),
            Host::Domain(domain) => formatter.write_fmt(format_args!("{}", domain)),
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
pub struct NetAddr {
    pub host: Host,
    pub port: u16,
}

impl NetAddr {
    pub fn new(host: &str, port: u16) -> Self {
        // IPv6 assumed if square brackets are found
        let host = if host.find('[').is_some() && host.rfind(']').is_some() {
            &host[1..(host.len() - 1)]
        } else {
            host
        };
        NetAddr {
            host: match host.parse::<IpAddr>() {
                Ok(ip) => Host::IP(ip),
                _ => Host::Domain(host.to_string()),
            },
            port,
        }
    }

    pub fn from_domain(domain: String, port: u16) -> Self {
        NetAddr {
            host: Host::Domain(domain),
            port,
        }
    }

    pub fn from_ip(ip: IpAddr, port: u16) -> Self {
        NetAddr {
            host: Host::IP(ip),
            port,
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        NetAddr {
            host: Host::IP(addr.ip()),
            port: addr.port(),
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self.host, Host::Domain(_))
    }

    pub fn is_ip(&self) -> bool {
        !self.is_domain()
    }

    pub fn is_ipv6(&self) -> bool {
        match self.host {
            Host::IP(ip) => ip.is_ipv6(),
            _ => false,
        }
    }

    pub fn unwrap_domain(&self) -> &str {
        if let Host::Domain(ref domain) = self.host {
            domain.as_str()
        } else {
            panic!("not a domain")
        }
    }

    pub fn unwrap_ip(&self) -> IpAddr {
        if let Host::IP(ref ip) = self.host {
            *ip
        } else {
            panic!("not an IP")
        }
    }

    pub fn is_loopback(&self) -> bool {
        if let Host::IP(ref ip) = self.host {
            ip.is_loopback()
        } else {
            false
        }
    }

    pub fn is_internal_ip(&self) -> bool {
        if let Host::IP(ref ip) = self.host {
            match ip {
                IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
                IpAddr::V6(ip) => ip.is_loopback(),
            }
        } else {
            false
        }
    }

    pub fn is_internal_domain(&self) -> bool {
        if let Host::Domain(ref domain) = self.host {
            INTERNAL_DOMAIN_SURRFIX
                .iter()
                .any(|suffix| domain.ends_with(suffix))
        } else {
            false
        }
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self.host {
            Host::IP(ip) => Some(SocketAddr::new(ip, self.port)),
            _ => {
                warn!("{self} is not an IP address");
                None
            }
        }
    }
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.host {
            Host::IP(ip) if ip.is_ipv6() => {
                formatter.write_fmt(format_args!("[{}]:{}", self.host, self.port))
            }
            _ => formatter.write_fmt(format_args!("{}:{}", self.host, self.port)),
        }
    }
}

impl FromStr for NetAddr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let colon_pos = s.rfind(':').context("port required")?;
        let port = s[(colon_pos + 1)..]
            .parse::<u16>()
            .context("invalid port")?;

        if let Some(pos) = s.rfind(']') {
            if pos + 1 != colon_pos {
                bail!("invalid ipv6 address: {s}");
            }
        }

        Ok(NetAddr::new(&s[..colon_pos], port))
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum ProtoType {
    Http,
    Socks5,
    Socks4,
    Tcp,
    Udp,
}

impl ProtoType {
    pub fn format_as_string(&self, combine_layer_proto: bool) -> String {
        match self {
            ProtoType::Http => {
                if combine_layer_proto {
                    "http+quic"
                } else {
                    "http"
                }
            }
            ProtoType::Socks5 => {
                if combine_layer_proto {
                    "socks5+quic"
                } else {
                    "socks5"
                }
            }
            ProtoType::Socks4 => {
                if combine_layer_proto {
                    "socks4+quic"
                } else {
                    "socks4"
                }
            }
            ProtoType::Tcp => {
                if combine_layer_proto {
                    "tcp+quic"
                } else {
                    "tcp"
                }
            }
            ProtoType::Udp => {
                if combine_layer_proto {
                    "udp+quic"
                } else {
                    "udp"
                }
            }
        }
        .to_string()
    }
}

impl std::fmt::Display for ProtoType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let msg = match self {
            ProtoType::Http => "HTTP",
            ProtoType::Socks5 => "SOCKS5",
            ProtoType::Socks4 => "SOCKS4",
            ProtoType::Tcp => "TCP",
            ProtoType::Udp => "UDP",
        };
        formatter.write_fmt(format_args!("{}", msg))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum QuicProtoType {
    HttpOverQuic,
    Socks5OverQuic,
    Socks4OverQuic,
    TcpOverQuic,
    UdpOverQuic,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ServerAddr {
    pub proto: Option<ProtoType>,
    pub net_addr: NetAddr,
    pub is_quic_proto: bool,
}

impl Display for ServerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.proto {
            Some(pt) => f.write_fmt(format_args!(
                "{}://{}",
                pt.format_as_string(self.is_quic_proto),
                self.net_addr
            )),
            None => f.write_fmt(format_args!("{}", self.net_addr)),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    server_addr: ServerAddr,
    upstream_addr: Option<ServerAddr>,
    pub proxy_rules_file: String,
    pub workers: usize,
    pub dot_server: String,
    pub name_servers: String,
    pub watch_proxy_rules_change: bool,
    pub tcp_nodelay: bool,
    pub tcp_timeout_ms: u64,
    pub udp_timeout_ms: u64,
}

#[derive(Debug)]
pub struct QuicServerConfig {
    pub server_addr: SocketAddr,
    pub tcp_upstream: Option<SocketAddr>,
    pub udp_upstream: Option<SocketAddr>,
    pub common_cfg: CommonQuicConfig,
}

#[derive(Debug, Clone)]
pub struct QuicClientConfig {
    pub server_addr: NetAddr,
    pub local_tcp_server_addr: Option<SocketAddr>,
    pub local_udp_server_addr: Option<SocketAddr>,
    pub common_cfg: CommonQuicConfig,
    pub dot_servers: Vec<String>,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AddressMapping {
    pub server_addr: NetAddr,
    pub local_tcp_server_addr: Option<SocketAddr>,
    pub local_udp_server_addr: Option<SocketAddr>,
    pub common_cfg: CommonQuicConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommonQuicConfig {
    pub cert: String,
    pub key: String,
    pub cipher: String,
    pub password: String,
    pub quic_timeout_ms: u64,
    pub tcp_timeout_ms: u64,
    pub udp_timeout_ms: u64,
    pub retry_interval_ms: u64,
    pub workers: usize,
}

pub fn local_socket_addr(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }
}

pub fn unspecified_socket_addr(ipv6: bool) -> SocketAddr {
    if ipv6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

pub fn parse_socket_addr(addr: &str) -> Option<SocketAddr> {
    let mut addr = addr.to_string();
    let mut start_pos = 0;
    if let Some(ipv6_end_bracket_pos) = addr.find(']') {
        start_pos = ipv6_end_bracket_pos + 1;
    }
    if addr[start_pos..].find(':').is_none() {
        addr = format!("127.0.0.1:{}", addr);
    }
    addr.parse().ok()
}

#[rustfmt::skip]
pub fn parse_server_addr(addr: &str) -> Result<Option<ServerAddr>> {
    if addr.trim().is_empty() {
        return Ok(None);
    }

    let supported_protocols: &[(Option<ProtoType>, Option<QuicProtoType>, &str)] = &[
        (None, None, "unspecified"),
        (Some(ProtoType::Http), None, "http"),
        (Some(ProtoType::Socks5), None, "socks5"),
        (Some(ProtoType::Socks4), None, "socks4"),
        (Some(ProtoType::Tcp), None, "tcp"),
        (Some(ProtoType::Udp), None, "udp"),
        (Some(ProtoType::Http), Some(QuicProtoType::HttpOverQuic), "http+quic"),
        (Some(ProtoType::Socks5), Some(QuicProtoType::Socks5OverQuic), "socks5+quic"),
        (Some(ProtoType::Socks4), Some(QuicProtoType::Socks4OverQuic), "socks4+quic"),
        (Some(ProtoType::Tcp), Some(QuicProtoType::TcpOverQuic), "tcp+quic"),
        (Some(ProtoType::Udp), Some(QuicProtoType::UdpOverQuic), "udp+quic"),
    ];

    let addr = format_addr(addr, "127.0.0.1")?;
    let url = match Url::parse(addr.as_str()) {
        Ok(url) => url,
        _ => {
            log_and_bail!("invalid protocol: {addr}");
        }
    };

    if !url.has_host() {
        log_and_bail!("invalid address: {addr}");
    }

    let mut serv_proto = None;
    let mut quic_proto = None;
    supported_protocols.iter().for_each(|v| {
        if url.scheme() == v.2 {
            serv_proto = v.0.clone();
            quic_proto = v.1.clone();
        }
    });

    if url.scheme() != "unspecified" && serv_proto.is_none() {
        log_and_bail!("invalid scheme: {}", url.scheme());
    }

    let net_addr = NetAddr::new(
        url.host().unwrap().to_string().as_str(),
        url.port_or_known_default().unwrap(),
    );

    Ok(Some(ServerAddr{
        proto: serv_proto,
        net_addr,
        is_quic_proto: quic_proto.is_some(),
    }))
}

fn format_addr(addr: &str, default_ip: &str) -> Result<String> {
    let addr = if addr.contains("://") {
        addr.to_string()
    } else if addr.starts_with('[') && !addr.contains("]:") {
        log_and_bail!("Server address must contain a port, e.g. [::1]:3515");
    } else if addr.contains('.') && !addr.contains(':') {
        log_and_bail!("Server address must contain a port, e.g. 127.0.0.1:3515");
    } else if !addr.contains(':') {
        format!("unspecified://{default_ip}:{addr}")
    } else {
        format!("unspecified://{addr}")
    };
    Ok(addr)
}

#[rustfmt::skip]
pub fn create_config(
    server_addr: String,
    upstream_addr: String,
    dot_server: String,
    name_servers: String,
    proxy_rules_file: String,
    workers: usize,
    watch_proxy_rules_change: bool,
    tcp_nodelay: bool,
    mut tcp_timeout_ms: u64,
    mut udp_timeout_ms: u64,
) -> Result<Config> {
    let server_addr = match parse_server_addr(&server_addr)? {
        Some(server_addr) => server_addr,
        None => {
            log_and_bail!("invalid server address: {server_addr}");
        }
    };

    let upstream_addr = parse_server_addr(&upstream_addr)?;

    if tcp_timeout_ms == 0 {
        tcp_timeout_ms = 30000;
    }
    if udp_timeout_ms == 0 {
        udp_timeout_ms = 5000;
    }

    #[allow(warnings)]
    if let Some(upstream_addr) = &upstream_addr {
        if server_addr.is_quic_proto && upstream_addr.is_quic_proto {
            log_and_bail!(
                "QUIC server and QUIC upstream cannot be chained: {} -> {upstream_addr}",
                server_addr.net_addr.to_socket_addr().unwrap()
            );
        }

        if upstream_addr.net_addr.is_domain() && !upstream_addr.is_quic_proto {
            log_and_bail!("only IP address is allowed for upstream with non-quic protocols, invalid upstream: {upstream_addr}");
        }
    }

    match (server_addr.proto.clone(), upstream_addr.as_ref().and_then(|u| u.proto.clone())) {
        (None, Some(ProtoType::Http)) |
        (None, Some(ProtoType::Socks5)) |
        (None, Some(ProtoType::Socks4)) |
        (Some(ProtoType::Http), Some(ProtoType::Http)) |
        (Some(ProtoType::Http), Some(ProtoType::Socks5)) |
        (Some(ProtoType::Http), Some(ProtoType::Socks4)) |
        (Some(ProtoType::Http), None) |
        (Some(ProtoType::Socks5), Some(ProtoType::Http)) |
        (Some(ProtoType::Socks5), Some(ProtoType::Socks5)) |
        (Some(ProtoType::Socks5), Some(ProtoType::Socks4)) |
        (Some(ProtoType::Socks5), None) |
        (Some(ProtoType::Socks4), Some(ProtoType::Http)) |
        (Some(ProtoType::Socks4), Some(ProtoType::Socks5)) |
        (Some(ProtoType::Socks4), Some(ProtoType::Socks4)) |
        (Some(ProtoType::Socks4), None) |
        (Some(ProtoType::Tcp), Some(ProtoType::Tcp)) |
        (Some(ProtoType::Udp), Some(ProtoType::Udp)) |
        (None, None) => {}
        _ => {
            log_and_bail!("proto chaining not supported: {server_addr} →  {:?}",
                upstream_addr.as_ref().map_or("".to_string(), |u| u.net_addr.to_string()));
        }
    }

    let worker_threads = if workers > 0 {
        workers
    } else {
        num_cpus::get()
    };

    Ok(Config {
        server_addr,
        upstream_addr,
        proxy_rules_file,
        workers: worker_threads,
        dot_server,
        name_servers,
        watch_proxy_rules_change,
        tcp_nodelay,
        tcp_timeout_ms,
        udp_timeout_ms
    })
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::sys::{jlong, jstring};

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_TRUE};
    use self::jni::JNIEnv;
    use super::*;
    use log::error;
    use std::sync::Arc;
    use std::thread;

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeInitLogger(
        mut env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        let log_level = match get_string(&mut env, &jlogLevel).as_str() {
            "T" => "trace",
            "D" => "debug",
            "I" => "info",
            "W" => "warn",
            "E" => "error",
            _ => "info",
        };
        let log_filter = format!(
            "omnip={},rstun={},rs_utilities={}",
            log_level, log_level, log_level
        );
        rs_utilities::LogHelper::init_logger("omnip", log_filter.as_str());
        return JNI_TRUE;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeCreate(
        mut env: JNIEnv,
        _: JClass,
        jaddr: JString,
        jupstream: JString,
        jdotServer: JString,
        jnameServers: JString,
        jproxyRulesFile: JString,
        jcert: JString,
        jkey: JString,
        jcipher: JString,
        jpassword: JString,
        jquicTimeoutMs: jint,
        jretryIntervalMs: jint,
        jworkers: jint,
        jtcpNoDelay: jboolean,
        jtcpTimeoutMs: jlong,
        judpTimeoutMs: jlong,
    ) -> jlong {
        if jaddr.is_null() {
            return 0;
        }

        let addr = get_string(&mut env, &jaddr);
        let upstream = get_string(&mut env, &jupstream);
        let dot_server = get_string(&mut env, &jdotServer);
        let name_servers = get_string(&mut env, &jnameServers);
        let proxy_rules_file = get_string(&mut env, &jproxyRulesFile);
        let cert = get_string(&mut env, &jcert);
        let key = get_string(&mut env, &jkey);
        let cipher = get_string(&mut env, &jcipher);
        let password = get_string(&mut env, &jpassword);

        let config = match create_config(
            addr,
            upstream,
            dot_server,
            name_servers,
            proxy_rules_file,
            jworkers as usize,
            false,
            jtcpNoDelay != 0,
            jtcpTimeoutMs as u64,
            judpTimeoutMs as u64,
        ) {
            Ok(config) => config,
            Err(e) => {
                error!("failed to create config: {}", e);
                return 0;
            }
        };

        let common_quic_config = CommonQuicConfig {
            cert,
            key,
            password,
            cipher,
            quic_timeout_ms: jquicTimeoutMs as u64,
            retry_interval_ms: jretryIntervalMs as u64,
            workers: jworkers as usize,
            tcp_timeout_ms: jtcpTimeoutMs as u64,
            udp_timeout_ms: judpTimeoutMs as u64,
        };

        Box::into_raw(Box::new(Server::new(config, common_quic_config))) as jlong
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeStart(
        _env: JNIEnv,
        _: JClass,
        server_ptr: jlong,
    ) {
        if server_ptr == 0 {
            return;
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        if server.has_scheduled_start() {
            return;
        }

        server.set_scheduled_start();
        thread::spawn(move || {
            let server = &mut *(server_ptr as *mut Arc<Server>);
            server.run().ok();
        });
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeGetState(
        env: JNIEnv,
        _: JClass,
        server_ptr: jlong,
    ) -> jstring {
        if server_ptr == 0 {
            return env.new_string("").unwrap().into_raw();
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        env.new_string(server.get_state().to_string())
            .unwrap()
            .into_raw()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeStop(
        _env: JNIEnv,
        _: JClass,
        server_ptr: jlong,
    ) {
        if server_ptr != 0 {
            let _boxed_server = Box::from_raw(server_ptr as *mut Arc<Server>);
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_omnip_Omnip_nativeSetEnableOnInfoReport(
        env: JNIEnv,
        jobj: JClass,
        server_ptr: jlong,
        enable: jboolean,
    ) {
        if server_ptr == 0 {
            return;
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        let bool_enable = enable == 1;
        if bool_enable && !server.has_on_info_listener() {
            let jvm = env.get_java_vm().unwrap();
            let jobj_global_ref = env.new_global_ref(jobj).unwrap();
            server.set_on_info_listener(move |data: &str| {
                let mut env = jvm.attach_current_thread().unwrap();
                if let Ok(s) = env.new_string(data) {
                    env.call_method(
                        &jobj_global_ref,
                        "onInfo",
                        "(Ljava/lang/String;)V",
                        &[(&s).into()],
                    )
                    .unwrap();
                }
            });
        }

        server.set_enable_on_info_report(bool_enable);
    }

    fn get_string(env: &mut JNIEnv, jstr: &JString) -> String {
        if !jstr.is_null() {
            env.get_string(&jstr).unwrap().to_string_lossy().to_string()
        } else {
            String::from("")
        }
    }
}
