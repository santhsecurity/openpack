use openpack::OpenPack;
use std::env;
use std::io::Write;
use zip::write::SimpleFileOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = if let Some(path) = env::args().nth(1) {
        std::path::PathBuf::from(path)
    } else {
        create_example_archive()?
    };
    let pack = OpenPack::open_default(&path)?;
    println!("format={}", pack.format());
    println!("entry count={}", pack.entries()?.len());
    println!("mapped bytes={}", pack.mmap().len());
    for entry in pack.entries()? {
        println!(
            "{} dir={} size={} comp={}",
            entry.name, entry.is_dir, entry.uncompressed_size, entry.compressed_size
        );
    }
    Ok(())
}

fn create_example_archive() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("inspect.zip");
    let file = std::fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", SimpleFileOptions::default())?;
    zip.write_all(b"hello from openpack")?;
    zip.finish()?;
    let persisted = dir.keep();
    Ok(persisted.join("inspect.zip"))
}
