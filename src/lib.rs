mod http_parser;
mod proxy_rule_manager;
mod server;
mod stat;

use anyhow::Result;
use byte_pool::BytePool;
pub use proxy_rule_manager::ProxyRuleManager;
pub use server::Server;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::sync::Arc;

type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Default, Debug)]
pub struct NetAddr {
    pub host: String, // domain or ip
    pub port: u16,
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        formatter.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

#[derive(Debug)]
pub struct Config {
    pub addr: SocketAddr,
    pub downstream_addr: Option<SocketAddr>,
    pub proxy_rules_file: String,
    pub threads: usize,
    pub dot_server: String,
    pub name_servers: String,
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

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use jni::objects::JObject;
    use jni::sys::jlong;

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
        };

        Box::into_raw(Box::new(Server::new(config))) as jlong
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeStart(
        _env: JNIEnv,
        _: JObject,
        server_ptr: jlong,
    ) {
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
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeIsRunning(
        _env: JNIEnv,
        _: JObject,
        server_ptr: jlong,
    ) -> jboolean {
        let server = &mut *(server_ptr as *mut Server);
        server.is_running() as jboolean
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeStop(
        _env: JNIEnv,
        _: JObject,
        server_ptr: jlong,
    ) {
        let _boxed_server = Box::from_raw(server_ptr as *mut Server);
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_nativeSetEnableStat(
        env: JNIEnv,
        jobj: JObject,
        server_ptr: jlong,
        enable: jboolean,
    ) {
        let server = &mut *(server_ptr as *mut Server);
        if !server.has_stat_callback() {
            let jvm = env.get_java_vm().unwrap();
            let jobj_global_ref = env.new_global_ref(jobj).unwrap();
            server.set_stat_callback(move |data: &str| {
                let env = jvm.attach_current_thread().unwrap();
                if let Ok(s) = env.new_string(data) {
                    env.call_method(
                        &jobj_global_ref,
                        "onStat",
                        "(Ljava/lang/String;)V",
                        &[s.into()],
                    )
                    .unwrap();
                }
            });
            server.set_enable_stat(true);
        }

        server.set_enable_stat(enable != 0);
    }
}
