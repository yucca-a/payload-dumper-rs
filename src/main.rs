use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

use payload_dumper::payload::Payload;

/// Fast Android OTA payload.bin dumper.
///
/// Supports local files, ZIP archives, and HTTP/HTTPS URLs with Range requests.
#[derive(Parser)]
#[command(name = "payload-dumper", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List partitions in a payload without extracting.
    List {
        /// payload.bin / OTA ZIP file path or URL.
        source: String,
    },

    /// Extract partitions from a payload.
    Extract {
        /// payload.bin / OTA ZIP file path or URL.
        source: String,

        /// Output directory (created if absent). Default: ./output
        #[arg(short, long, default_value = "output")]
        out: PathBuf,

        /// Comma-separated partition names to extract (default: all).
        #[arg(short, long)]
        partitions: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::List { source } => {
            let payload = open_payload(&source)?;
            println!("{:<20} {:>12}  ops", "Partition", "Size");
            println!("{}", "-".repeat(40));
            for p in payload.list_partitions() {
                println!(
                    "{:<20} {:>12}  {}",
                    p.name,
                    payload_dumper::human_size(p.size_bytes),
                    p.num_operations
                );
            }
        }

        Cmd::Extract { source, out, partitions } => {
            let payload = open_payload(&source)?;

            let names: Vec<String> = partitions
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect();

            // Show what we're about to extract
            let parts = payload.list_partitions();
            let targets: Vec<_> = if names.is_empty() {
                parts.iter().collect()
            } else {
                parts.iter().filter(|p| names.contains(&p.name)).collect()
            };

            println!("Extracting {} partition(s) to {}", targets.len(), out.display());

            let pb = ProgressBar::new(targets.len() as u64);
            pb.set_style(
                ProgressStyle::with_template("[{elapsed_precise}] {bar:40} {pos}/{len} {msg}")
                    .unwrap(),
            );

            std::fs::create_dir_all(&out).context("create output directory")?;
            payload.extract(&out, &names)?;
            pb.finish_with_message("Done");
        }
    }

    Ok(())
}

/// Open a Payload from a local path or URL.
fn open_payload(source: &str) -> Result<Payload> {
    if source.starts_with("http://") || source.starts_with("https://") {
        // Auto-detect: if URL ends with .zip → parse as OTA ZIP via Central Directory
        if source.to_lowercase().ends_with(".zip") {
            eprintln!("[*] Detected OTA ZIP URL, parsing Central Directory...");
            Payload::open_zip_url(source).with_context(|| format!("open ZIP URL: {source}"))
        } else {
            eprintln!("[*] Detected payload.bin URL");
            Payload::open_url(source).with_context(|| format!("open URL: {source}"))
        }
    } else {
        let path = std::path::Path::new(source);
        let name_lc = source.to_lowercase();
        if name_lc.ends_with(".zip") {
            // Local ZIP: use open_at with offset 0 fallback to open_at
            // Try zero-copy STORED entry detection via zip crate
            open_local_zip(path)
        } else {
            Payload::open(path).with_context(|| format!("open {source}"))
        }
    }
}

/// Open a payload.bin from a local ZIP file.
/// If payload.bin is STORED, reads directly without extracting.
fn open_local_zip(zip_path: &std::path::Path) -> Result<Payload> {
    use zip::ZipArchive;

    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("open {}", zip_path.display()))?;
    let mut archive = ZipArchive::new(file)
        .with_context(|| format!("parse ZIP: {}", zip_path.display()))?;

    let entry = archive
        .by_name("payload.bin")
        .context("payload.bin not found in ZIP")?;

    if entry.compression() == zip::CompressionMethod::Stored {
        let offset = entry.data_start();
        drop(entry);
        drop(archive);
        eprintln!("[*] payload.bin STORED at offset {offset} (zero-copy)");
        Payload::open_at(zip_path, offset)
    } else {
        drop(entry);
        drop(archive);
        // Compressed payload.bin — extract to temp
        eprintln!("[*] payload.bin is compressed, extracting to temp...");
        let tmp = tempfile::tempdir().context("create temp dir")?;
        let tmp_payload = tmp.path().join("payload.bin");
        let mut archive = ZipArchive::new(
            std::fs::File::open(zip_path)
                .with_context(|| format!("open {}", zip_path.display()))?,
        )?;
        let mut entry = archive.by_name("payload.bin")?;
        let mut out = std::fs::File::create(&tmp_payload)?;
        std::io::copy(&mut entry, &mut out)?;
        drop(out);
        let payload = Payload::open(&tmp_payload)?;
        // Keep tmp alive by leaking — process will clean up on exit
        std::mem::forget(tmp);
        Ok(payload)
    }
}
