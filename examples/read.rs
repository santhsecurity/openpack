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
    let name = env::args()
        .nth(2)
        .unwrap_or_else(|| "hello.txt".to_string());

    let pack = OpenPack::open_default(&path)?;
    let data = pack.read_entry(&name)?;
    println!("{} bytes", data.len());
    println!("{}", String::from_utf8_lossy(&data));
    Ok(())
}

fn create_example_archive() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("example.zip");
    let file = std::fs::File::create(&path)?;
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file("hello.txt", SimpleFileOptions::default())?;
    zip.write_all(b"hello from openpack")?;
    zip.finish()?;
    let persisted = dir.keep();
    Ok(persisted.join("example.zip"))
}
