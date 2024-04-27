use std::{env, error::Error, path::Path};

// build the web project before building the crate
// cd omnip-web
// npm run build

fn main() -> Result<(), Box<dyn Error>> {
    let src_dir = "src/omnip-web/dist/";
    let out_dir = env::var("OUT_DIR")?;
    let archive_file_path = Path::new(&out_dir).join("omnip-web.blob");
    // index into the omnip-web.blob file, in the format of [filepath offset length]
    let archive_index_file_path = Path::new(&out_dir).join("omnip-web.idx");

    monolithica::AssetArhiver::create_archive(
        src_dir,
        archive_file_path.as_path(),
        archive_index_file_path.as_path(),
        true,
    )?;

    Ok(())
}
