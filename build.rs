use std::{
    env,
    error::Error,
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

const SOURCE_DIR: &str = &"src/rsproxy-web/dist/";

// cd rsproxy-web
// npm run build

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = env::var("OUT_DIR")?;
    let blob_file_path = Path::new(&out_dir).join("rsproxy-web.blob");
    // index into the rsproxy-web.blob file, in the format of [filepath offset length]
    let blob_index_file_path = Path::new(&out_dir).join("rsproxy-web.idx");

    let mut blob_file = File::create(&blob_file_path)?;
    let mut blob_index_file = File::create(&blob_index_file_path)?;
    let mut offset = 0u64;

    copy_web_assets(
        SOURCE_DIR,
        &mut blob_file,
        &mut blob_index_file,
        &mut offset,
    )
}

fn copy_web_assets(
    source_dir: &str,
    blob_file: &mut File,
    blob_index_file: &mut File,
    offset: &mut u64,
) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;

        let path = entry.path();
        if path.is_file() {
            let mut file = File::open(&path)?;
            let file_len = file.metadata().unwrap().len();

            writeln!(
                blob_index_file,
                "/{} {} {}",
                &path.to_path_buf().to_str().unwrap()[SOURCE_DIR.len()..],
                offset,
                file_len
            )?;

            *offset += file_len;

            let mut buffer = [0u8; 4096];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                blob_file.write_all(&buffer[..bytes_read])?;
            }
        } else if path.is_dir() {
            copy_web_assets(path.to_str().unwrap(), blob_file, blob_index_file, offset)?;
        }
    }

    Ok(())
}
