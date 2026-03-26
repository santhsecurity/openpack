use openpack::{Limits, OpenPack};
use std::env;
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = if let Some(path) = env::args().nth(1) {
        std::path::PathBuf::from(path)
    } else {
        create_example_archive()?
    };
    let cfg = env::args().nth(2);

    let limits = match cfg {
        Some(cfg_path) => Limits::from_toml_file(Path::new(&cfg_path))?,
        None => Limits::default(),
    };

    let pack = OpenPack::open(&path, limits)?;
    println!("entries={}", pack.entries()?.len());
    Ok(())
}

fn create_example_archive() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("limits.zip");
    let file = std::fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", SimpleFileOptions::default())?;
    zip.write_all(b"hello from openpack")?;
    zip.finish()?;
    let persisted = dir.keep();
    Ok(persisted.join("limits.zip"))
}
