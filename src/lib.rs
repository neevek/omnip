mod http_parser;
mod proxy_rule_manager;
mod server;

use anyhow::Result;
use byte_pool::BytePool;
use log::{error, info, warn};
use notify::{watcher, DebouncedEvent, RecursiveMode, Watcher};
pub use proxy_rule_manager::ProxyRuleManager;
pub use server::Server;
use std::fmt::Formatter;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::mpsc::channel;
use std::sync::{Arc, Once, RwLock};
use std::time::Duration;

static INIT_LOGGER_ONCE: Once = Once::new();
static mut IS_RUNNING: bool = false;

type BufferPool = Arc<BytePool<Vec<u8>>>;

fn new_buffer_pool() -> BufferPool {
    Arc::new(BytePool::<Vec<u8>>::new())
}

#[derive(Default, Debug)]
pub struct NetAddr {
    pub host: String, // domain or ip
    pub port: u16,
}

impl NetAddr {
    fn as_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
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
}

pub fn init_logger(log_level: &str) {
    INIT_LOGGER_ONCE.call_once(|| LogHelper::init_logger(log_level.as_ref()));
}

pub fn serve(config: Config) {
    unsafe {
        if IS_RUNNING {
            warn!("rsproxy is alreay running");
            return;
        }
    }

    if !config.proxy_rules_file.is_empty() {
        if !Path::new(&config.proxy_rules_file).is_file() {
            error!(
                "proxy rules file does not exist: {}",
                config.proxy_rules_file
            );
            return;
        }
    }

    if let Some(addr) = config.downstream_addr {
        info!("using downstream: {}", addr);
    }

    let worker_threads = if config.threads > 0 {
        config.threads
    } else {
        num_cpus::get()
    };
    info!("will use {} worker threads", worker_threads);

    unsafe { IS_RUNNING = true }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            run(config).await.unwrap();
        });

    unsafe { IS_RUNNING = false }
}

pub fn is_running() -> bool {
    unsafe { IS_RUNNING }
}

pub fn parse_sock_addr(addr: &str) -> Option<SocketAddr> {
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

async fn run(config: Config) -> Result<()> {
    let mut proxy_rule_manager = None;
    if !config.proxy_rules_file.is_empty() {
        let mut prm = ProxyRuleManager::new();
        let count = prm.add_rules_by_file(config.proxy_rules_file.as_str());
        let prm = Arc::new(RwLock::new(prm));
        proxy_rule_manager = Some(prm.clone());

        info!(
            "{} proxy rules added with file: {}",
            count, config.proxy_rules_file
        );

        watch_proxy_rules_file(config.proxy_rules_file.clone(), prm);
    }

    let mut server = Server::new(config.addr, config.downstream_addr, proxy_rule_manager);
    server.bind().await?;
    server.start().await?;
    Ok(())
}

fn watch_proxy_rules_file(proxy_rules_file: String, prm: Arc<RwLock<ProxyRuleManager>>) {
    std::thread::spawn(move || {
        let (tx, rx) = channel();
        let mut watcher = watcher(tx, Duration::from_secs(5))?;
        watcher.watch(proxy_rules_file.as_str(), RecursiveMode::NonRecursive)?;

        loop {
            match rx.recv() {
                Ok(DebouncedEvent::Create(_))
                | Ok(DebouncedEvent::NoticeWrite(_))
                | Ok(DebouncedEvent::Write(_)) => {
                    let mut prm = prm.write().unwrap();

                    prm.clear_all();
                    let count = prm.add_rules_by_file(proxy_rules_file.as_str());

                    info!(
                        "updated proxy rules from file: {}, rules updated: {}",
                        proxy_rules_file, count
                    );
                }
                Err(e) => {
                    error!("watch error: {:?}", e);
                    break;
                }
                _ => {}
            }
        }

        Result::<()>::Ok(())
    });
}

#[cfg(not(target_os = "android"))]
macro_rules! colored_log {
    ($buf:ident, $record:ident, $term_color:literal, $level:literal) => {{
        let filename = $record.file().unwrap_or("unknown");
        let filename = &filename[filename.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
        writeln!(
            $buf,
            concat!($term_color, "{} [{}:{}] [", $level, "] {}\x1B[0m"),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S.%3f"),
            filename,
            $record.line().unwrap_or(0),
            $record.args()
        )
    }};
}

struct LogHelper {}
impl LogHelper {
    #[cfg(not(target_os = "android"))]
    pub fn init_logger(log_level_str: &str) {
        use std::io::Write;
        let log_level_filter;
        match log_level_str.as_ref() {
            "D" => log_level_filter = log::LevelFilter::Debug,
            "I" => log_level_filter = log::LevelFilter::Info,
            "W" => log_level_filter = log::LevelFilter::Warn,
            "E" => log_level_filter = log::LevelFilter::Error,
            _ => log_level_filter = log::LevelFilter::Trace,
        }

        pretty_env_logger::formatted_timed_builder()
            .format(|buf, record| match record.level() {
                log::Level::Trace => colored_log!(buf, record, "\x1B[0m", "T"),
                log::Level::Debug => colored_log!(buf, record, "\x1B[92m", "D"),
                log::Level::Info => colored_log!(buf, record, "\x1B[34m", "I"),
                log::Level::Warn => colored_log!(buf, record, "\x1B[93m", "W"),
                log::Level::Error => colored_log!(buf, record, "\x1B[31m", "E"),
            })
            .filter(Some("rsproxy"), log_level_filter)
            .init();
    }

    #[cfg(target_os = "android")]
    pub fn init_logger(log_level_str: &str) {
        let log_level;
        match log_level_str.as_ref() {
            "D" => log_level = log::Level::Debug,
            "I" => log_level = log::Level::Info,
            "W" => log_level = log::Level::Warn,
            "E" => log_level = log::Level::Error,
            _ => log_level = log::Level::Trace,
        }

        android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(log_level)
                .with_tag("rsproxy"),
        );
    }
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
pub mod android {
    extern crate jni;

    use self::jni::objects::{JClass, JString};
    use self::jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
    use self::jni::{JNIEnv, JavaVM};
    use super::*;
    use std::os::raw::c_void;
    use std::thread::{self, sleep};

    #[no_mangle]
    pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
        let _env = vm.get_env().expect("failed to get JNIEnv");
        JNI_VERSION_1_6
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_initLogger(
        env: JNIEnv,
        _: JClass,
        jlogLevel: JString,
    ) -> jboolean {
        if let Ok(log_level) = env.get_string(jlogLevel) {
            init_logger(log_level.to_str().unwrap());
            return JNI_TRUE;
        }
        JNI_FALSE
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_isRunning(
        _env: JNIEnv,
        _: JClass,
    ) -> jboolean {
        return if is_running() { JNI_TRUE } else { JNI_FALSE };
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_net_neevek_rsproxy_RsProxy_start(
        env: JNIEnv,
        _: JClass,
        jaddr: JString,
        jdownstream: JString,
        jproxyRulesFile: JString,
        jthreads: jint,
    ) -> jboolean {
        if jaddr.is_null() {
            return JNI_FALSE;
        }

        let str_addr: String = env.get_string(jaddr).unwrap().into();
        let addr = parse_sock_addr(&str_addr);
        if addr.is_none() {
            error!("invalid address: {}", &str_addr);
            return JNI_FALSE;
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

        let config = Config {
            addr: addr.unwrap(),
            downstream_addr: parse_sock_addr(downstream.as_str()),
            proxy_rules_file,
            threads: jthreads as usize,
        };

        thread::spawn(|| serve(config));

        // wait for a moment for the server to start
        sleep(std::time::Duration::from_millis(500));

        return if IS_RUNNING { JNI_TRUE } else { JNI_FALSE };
    }
}
