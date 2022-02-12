use anyhow::Result;
use colored::Colorize;
use log::info;
use rsproxy::*;
use std::io::Write;

extern crate colored;
extern crate pretty_env_logger;

fn main() {
    let config = Config::default();

    LogHelper::init_logger(config.loglevel.as_ref());

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();

    let worker_threads = num_cpus::get() + 1;
    info!("will use {} worker threads", worker_threads);

    //let url = Url::parse("http://127.0.0.1:222/hello.html").unwrap();
    //let a = url.host_str().unwrap();
    //info!(">>>>>>>>>> haha: {}", a);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(worker_threads)
        .build()
        .unwrap()
        .block_on(async {
            run().await.unwrap();
        });
}

async fn run() -> Result<()> {
    let mut server = Server::new("0.0.0.0:1091".parse().unwrap(), "0.0.0.0:9800".parse().ok());
    server.bind().await?;
    server.start().await?;
    Ok(())
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
