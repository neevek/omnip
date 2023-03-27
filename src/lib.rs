mod http_parser;
mod proxy_rule_manager;
mod server;
mod server_info_bridge;
mod socks;
mod utils;

use anyhow::Result;
use byte_pool::BytePool;
use log::error;
pub use proxy_rule_manager::ProxyRuleManager;
pub use server::Server;
use std::fmt::Formatter;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

const INTERNAL_DOMAIN_SURRFIX: [&'static str; 5] =
    [".home", ".lan", ".corp", ".intranet", ".private"];

type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Debug)]
pub enum ProxyError {
    ConnectionRefused,
    IPv6NotSupported,       // not supported by Socks4
    DomainNameNotSupported, // not supported by Socks4
    InternalError,
    BadRequest,
    PayloadTooLarge,
    BadGateway(anyhow::Error),
    Disconnected(anyhow::Error),
}

#[derive(Debug)]
pub enum Host {
    IP(IpAddr),
    Domain(String),
}

#[derive(Debug)]
pub struct NetAddr {
    pub host: Host,
    pub port: u16,
}

impl NetAddr {
    pub fn new(host: &str, port: u16) -> Self {
        NetAddr {
            host: match host.parse::<IpAddr>() {
                Ok(ip) => Host::IP(ip),
                _ => Host::Domain(host.to_string()),
            },
            port,
        }
    }

    pub fn is_domain(&self) -> bool {
        if let Host::Domain(_) = self.host {
            true
        } else {
            false
        }
    }

    pub fn unwrap_domain(&self) -> &str {
        if let Host::Domain(ref domain) = self.host {
            domain.as_str()
        } else {
            panic!("not a domain")
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
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_fmt(format_args!("{:?}:{}", self.host, self.port))
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum DownstreamType {
    HTTP,
    SOCKS, // SOCKS5
    SOCKS5,
    SOCKS4,
}

#[derive(Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub downstream_type: Option<DownstreamType>,
    pub downstream_addr: Option<SocketAddr>,
    pub proxy_rules_file: String,
    pub threads: usize,
    pub dot_server: String,
    pub name_servers: String,
    pub watch_proxy_rules_change: bool,
}

pub fn parse_sock_addr(addr: &str) -> Option<SocketAddr> {
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

pub fn parse_downstream_addr(addr: &str) -> (Option<DownstreamType>, Option<SocketAddr>) {
    const SUPPORTED_PROTOCOLS: &[(DownstreamType, &str)] = &[
        (DownstreamType::HTTP, "http://"),
        (DownstreamType::SOCKS, "socks://"),
        (DownstreamType::SOCKS5, "socks5://"),
        (DownstreamType::SOCKS4, "socks4://"),
    ];

    let mut downstream_type = None;
    SUPPORTED_PROTOCOLS.iter().for_each(|v| {
        if addr.starts_with(v.1) {
            downstream_type = Some(v.0.clone());
        }
    });

    if downstream_type == None {
        if addr.find("://").is_some() {
            error!("invalid downstream protocol, address: {}", addr);
            return (None, None);
        }
        downstream_type = Some(DownstreamType::HTTP);
    }

    let start_index = addr.find("://").unwrap_or(0);
    let mut addr = addr[(start_index + 3)..].trim_end_matches("/").to_string();

    let mut start_pos = 0;
    if let Some(ipv6_end_bracket_pos) = addr.find(']') {
        start_pos = ipv6_end_bracket_pos + 1;
    }
    if addr[start_pos..].find(':').is_none() {
        addr = format!("127.0.0.1:{}", addr);
    }

    if let Ok(addr) = addr.parse() {
        return (downstream_type, Some(addr));
    }

    (None, None)
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::sys::{jlong, jstring};

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
    use self::jni::{JNIEnv, JavaVM};
    use super::*;
    use log::error;
    use std::os::raw::c_void;
    use std::thread;

    #[no_mangle]
    pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
        let _env = vm.get_env().expect("failed to get JNIEnv");
        JNI_VERSION_1_6
    }

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
        jdownstream: JString,
        jproxyRulesFile: JString,
        jdotServer: JString,
        jnameServers: JString,
        jthreads: jint,
    ) -> jlong {
        if jaddr.is_null() {
            return 0;
        }

        let str_addr: String = env.get_string(jaddr).unwrap().into();
        let addr = parse_sock_addr(&str_addr);
        if addr.is_none() {
            error!("invalid address: {}", &str_addr);
            return 0;
        }

        let downstream = if !jdownstream.is_null() {
            env.get_string(jdownstream).unwrap().into()
        } else {
            String::from("")
        };
        let proxy_rules_file = if !jproxyRulesFile.is_null() {
            env.get_string(jproxyRulesFile).unwrap().into()
        } else {
            String::from("")
        };
        let dotServer = if !jdotServer.is_null() {
            env.get_string(jdotServer).unwrap().into()
        } else {
            String::from("")
        };
        let nameServers = if !jnameServers.is_null() {
            env.get_string(jnameServers).unwrap().into()
        } else {
            String::from("")
        };

        let config = Config {
            addr: addr.unwrap(),
            downstream_addr: parse_sock_addr(downstream.as_str()),
            proxy_rules_file,
            threads: jthreads as usize,
            dot_server: dotServer,
            name_servers: nameServers,
            watch_proxy_rules_change: false,
        };

        Box::into_raw(Box::new(Server::new(config))) as jlong
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

        let server = &mut *(server_ptr as *mut Server);
        if server.has_scheduled_start() {
            return;
        }

        server.set_scheduled_start();
        thread::spawn(move || {
            let server = &mut *(server_ptr as *mut Server);
            server.start_and_block().ok();
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

        let server = &mut *(server_ptr as *mut Server);
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
            let _boxed_server = Box::from_raw(server_ptr as *mut Server);
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

        let server = &mut *(server_ptr as *mut Server);
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
}
