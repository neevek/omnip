mod api;
mod dashboard;
mod http;
mod proxy_handler;
mod proxy_rule_manager;
mod quic;
mod server;
mod server_info_bridge;
mod socks;
mod utils;

use anyhow::{bail, Result};
pub use api::Api;
use byte_pool::{Block, BytePool};
use lazy_static::lazy_static;
use log::{error, warn};
pub use proxy_rule_manager::ProxyRuleManager;
pub use quic::quic_client::QuicClient;
pub use quic::quic_server::QuicServer;
use rs_utilities::log_and_bail;
pub use server::Server;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::Url;

const INTERNAL_DOMAIN_SURRFIX: [&'static str; 6] = [
    ".home",
    ".lan",
    ".corp",
    ".intranet",
    ".private",
    "localhost ",
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
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetAddr {
    pub host: Host,
    pub port: u16,
}

impl NetAddr {
    pub fn new(host: &str, port: u16) -> Self {
        // IPv6 assumed if square brackets are found
        let host = if host.find('[').is_some() && host.find(']').is_some() {
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
        match self.host {
            Host::Domain(_) => true,
            _ => false,
        }
    }

    pub fn is_ip(&self) -> bool {
        !self.is_domain()
    }

    pub fn unwrap_domain(&self) -> &str {
        if let Host::Domain(ref domain) = self.host {
            domain.as_str()
        } else {
            panic!("not a domain")
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
                warn!("{} is not an IP address", self);
                None
            }
        }
    }
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum ProtoType {
    Http,
    Socks5,
    Socks4,
}

impl std::fmt::Display for ProtoType {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        let msg = match self {
            ProtoType::Http => "HTTP",
            ProtoType::Socks5 => "SOCKS5",
            ProtoType::Socks4 => "SOCKS4",
        };
        formatter.write_fmt(format_args!("{}", msg))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum LayeredProtoType {
    HttpOverQuic,
    Socks5OverQuic,
    Socks4OverQuic,
}

#[derive(Debug)]
pub struct Config {
    pub server_type: Option<ProtoType>,
    pub addr: SocketAddr,
    pub is_layered_proto: bool,
    pub upstream_type: Option<ProtoType>,
    pub upstream_addr: Option<NetAddr>,
    pub is_upstream_layered_proto: bool,
    pub proxy_rules_file: String,
    pub threads: usize,
    pub dot_server: String,
    pub name_servers: String,
    pub watch_proxy_rules_change: bool,
}

#[derive(Debug)]
pub struct QuicServerConfig {
    pub server_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub common_cfg: CommonQuicConfig,
}

#[derive(Debug)]
pub struct QuicClientConfig {
    pub server_addr: NetAddr,
    pub local_access_server_addr: SocketAddr,
    pub common_cfg: CommonQuicConfig,
}

#[derive(Debug, Clone)]
pub struct CommonQuicConfig {
    pub cert: String,
    pub key: String,
    pub cipher: String,
    pub password: String,
    pub max_idle_timeout_ms: u64,
}

pub fn local_ipv4_socket_addr_with_unspecified_port() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
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
pub fn parse_server_addr(
    addr: &str,
) -> (
    Option<ProtoType>,
    Option<NetAddr>,
    bool // is_layered_proto
) {
    if addr.trim().is_empty() {
        return (None, None, false);
    }

    let supported_protocols: &[(Option<ProtoType>, Option<LayeredProtoType>, &str)] = &[
        (None, None, "unspecified"),
        (Some(ProtoType::Http), None, "http"),
        (Some(ProtoType::Socks5), None, "socks5"),
        (Some(ProtoType::Socks4), None, "socks4"),
        (Some(ProtoType::Http), Some(LayeredProtoType::HttpOverQuic), "http+quic"),
        (Some(ProtoType::Socks5), Some(LayeredProtoType::Socks5OverQuic), "socks5+quic"),
        (Some(ProtoType::Socks4), Some(LayeredProtoType::Socks4OverQuic), "socks4+quic"),
    ];

    let addr = if addr.find("://").is_some() {
        addr.to_string()
    } else {
        if addr.rfind("]").is_none() && addr.find(":").is_none() {
            format!("unspecified://127.0.0.1:{}", addr)
        } else {
            format!("unspecified://{}", addr)
        }
    };

    let url = match Url::parse(addr.as_str()) {
        Ok(url) => url,
        _ => {
            error!("invalid server protocol, address: {}", addr);
            return (None, None, false);
        }
    };

    if !url.has_host() {
        error!("invalid server address: {}", addr);
        return (None, None, false);
    }

    let mut server_type = None;
    let mut layered_type = None;
    supported_protocols.iter().for_each(|v| {
        if url.scheme() == v.2 {
            server_type = v.0.clone();
            layered_type = v.1.clone();
        }
    });

    (
        server_type,
        Some(NetAddr::new(
            url.host().unwrap().to_string().as_str(),
            url.port_or_known_default().unwrap(),
        )),
        layered_type.is_some()
    )
}

pub fn create_config(
    addr: String,
    upstream: String,
    dot_server: String,
    name_servers: String,
    proxy_rules_file: String,
    threads: usize,
    watch_proxy_rules_change: bool,
) -> Result<Config> {
    let (server_type, orig_server_addr, is_layered_proto) = parse_server_addr(addr.as_str());

    let server_addr = match match orig_server_addr {
        Some(ref server_addr) => server_addr.to_socket_addr(),
        None => None,
    } {
        Some(server_addr) => server_addr,
        None => {
            log_and_bail!("server addr must be an IP address: {:?}", addr);
        }
    };

    let (upstream_type, upstream_addr, is_upstream_layered_proto) =
        parse_server_addr(upstream.as_str());
    if !upstream.is_empty() && upstream_type.is_none() {
        log_and_bail!("invalid upstream address: {}", upstream);
    }

    if is_layered_proto && is_upstream_layered_proto {
        log_and_bail!(
            "QUIC server and QUIC upstream cannot be chained: {} -> {:?}",
            server_addr,
            upstream_addr
        );
    } else if let Some(ref upstream) = upstream_addr {
        if upstream.is_domain() && !is_upstream_layered_proto {
            log_and_bail!("only IP address is allowed for upstream with non-layered protocols, invalid upstream: {}", upstream);
        }
    }

    let worker_threads = if threads > 0 {
        threads
    } else {
        num_cpus::get()
    };

    Ok(Config {
        server_type,
        addr: server_addr,
        is_layered_proto,
        upstream_type,
        upstream_addr,
        is_upstream_layered_proto,
        proxy_rules_file,
        threads: worker_threads,
        dot_server,
        name_servers,
        watch_proxy_rules_change,
    })
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::sys::{jlong, jstring};

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
    use self::jni::JNIEnv;
    use super::*;
    use log::error;
    use std::sync::Arc;
    use std::thread;

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeInitLogger(
        env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        if let Ok(log_level) = env.get_string(jlogLevel) {
            rs_utilities::LogHelper::init_logger("rsp", log_level.to_str().unwrap());
            return JNI_TRUE;
        }
        JNI_FALSE
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeCreate(
        env: JNIEnv,
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
        jmaxIdleTimeoutMs: jint,
        jthreads: jint,
    ) -> jlong {
        if jaddr.is_null() {
            return 0;
        }

        let addr = get_string(&env, &jaddr);
        let upstream = get_string(&env, &jupstream);
        let dot_server = get_string(&env, &jdotServer);
        let name_servers = get_string(&env, &jnameServers);
        let proxy_rules_file = get_string(&env, &jproxyRulesFile);
        let cert = get_string(&env, &jcert);
        let key = get_string(&env, &jkey);
        let cipher = get_string(&env, &jcipher);
        let password = get_string(&env, &jpassword);

        let config = match create_config(
            addr,
            upstream,
            dot_server,
            name_servers,
            proxy_rules_file,
            jthreads as usize,
            false,
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
            max_idle_timeout_ms: jmaxIdleTimeoutMs as u64,
        };

        Box::into_raw(Box::new(Server::new(config, common_quic_config))) as jlong
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeStart(
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
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeGetState(
        env: JNIEnv,
        _: JClass,
        server_ptr: jlong,
    ) -> jstring {
        if server_ptr == 0 {
            return env.new_string("").unwrap().into_inner();
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        env.new_string(server.get_state().to_string())
            .unwrap()
            .into_inner()
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeStop(
        _env: JNIEnv,
        _: JClass,
        server_ptr: jlong,
    ) {
        if server_ptr != 0 {
            let _boxed_server = Box::from_raw(server_ptr as *mut Arc<Server>);
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeSetEnableOnInfoReport(
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
                let env = jvm.attach_current_thread().unwrap();
                if let Ok(s) = env.new_string(data) {
                    env.call_method(
                        &jobj_global_ref,
                        "onInfo",
                        "(Ljava/lang/String;)V",
                        &[s.into()],
                    )
                    .unwrap();
                }
            });
        }

        server.set_enable_on_info_report(bool_enable);
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeSetPreferUpstream(
        env: JNIEnv,
        jobj: JClass,
        server_ptr: jlong,
        prefer_upstream: jboolean,
    ) {
        if server_ptr == 0 {
            return;
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        server.set_prefer_upstream(prefer_upstream == 1);
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeIsPreferUpstream(
        env: JNIEnv,
        jobj: JClass,
        server_ptr: jlong,
    ) -> jboolean {
        if server_ptr == 0 {
            return 0u8;
        }

        let server = &mut *(server_ptr as *mut Arc<Server>);
        if server.is_prefer_upstream() {
            1u8
        } else {
            0u8
        }
    }

    fn get_string(env: &JNIEnv, jstring: &JString) -> String {
        if !jstring.is_null() {
            env.get_string(*jstring).unwrap().into()
        } else {
            String::from("")
        }
    }
}
