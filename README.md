# payload-dumper-rs

[中文](docs/README.zh-CN.md)

A fast, native Rust reimplementation of Android OTA `payload.bin` dumper.

Compared to Python-based tools, this project adds:

1. Extract partitions directly from a **local ZIP** archive containing `payload.bin` without unzipping it (zero-copy for STORED entries).
2. Extract partitions directly from an **HTTP/HTTPS URL** — no need to download the entire OTA package. Only the bytes needed are fetched via HTTP Range requests.
3. **Parallel** extraction using all available CPU cores.
4. Full **ZIP64** support for OTA packages larger than 4 GB.
5. **Incremental (differential) OTA** support — `SOURCE_COPY`, `SOURCE_BSDIFF`, `BROTLI_BSDIFF` operations with both BSDIFF40 and BSDF2 patch formats.
6. **Metadata export** — dump comprehensive OTA metadata as JSON (partitions, dynamic partition groups, operation breakdown, etc.).
7. Works as both a **CLI tool** and a **Rust library**.

## Requirements

- Rust 1.80+ (edition 2024)
- `cargo`

## Installation

```bash
cargo install --git https://github.com/yucca-a/payload-dumper-rs
```

Or build from source:

```bash
git clone https://github.com/yucca-a/payload-dumper-rs
cd payload-dumper-rs
cargo build --release
# binary: target/release/payload-dumper
```

## Usage

### List partitions in a payload

```bash
# Local payload.bin
payload-dumper list payload.bin

# Local OTA ZIP
payload-dumper list ota.zip

# Remote URL — only downloads a few KB (Central Directory + manifest)
payload-dumper list https://example.com/ota.zip
```

### Extract all partitions

```bash
payload-dumper extract ota.zip --out ./output
```

### Extract specific partitions

Use a comma-separated list:

```bash
payload-dumper extract ota.zip --partitions boot,init_boot,vbmeta
```

### Extract from a remote URL

```bash
# Extract only boot and init_boot without downloading the full OTA
payload-dumper extract https://example.com/ota.zip -p boot,init_boot --out ./output
```

### Extract incremental (differential) OTA

Place old partition images in a directory (e.g. `old/boot.img`, `old/system.img`), then:

```bash
payload-dumper extract incremental_ota.zip --source-dir ./old --out ./output
```

### Export metadata as JSON

```bash
# Print to stdout
payload-dumper metadata ota.zip

# Save to file
payload-dumper metadata ota.zip -o metadata.json
```

## Library Usage

```rust
use payload_dumper::payload::Payload;
use std::path::Path;

// Local payload.bin
let p = Payload::open(Path::new("payload.bin"))?;

// Local ZIP (zero-copy for STORED entries)
let p = Payload::open_at(Path::new("ota.zip"), data_offset)?;

// Remote payload.bin URL
let p = Payload::open_url("https://example.com/payload.bin")?;

// Remote OTA ZIP URL (auto Range-based Central Directory parsing, ZIP64 compatible)
let p = Payload::open_zip_url("https://example.com/ota.zip")?;

// List partitions
for part in p.list_partitions() {
    println!("{}: {} bytes", part.name, part.size_bytes);
}

// Extract to directory (empty slice = all partitions)
p.extract(Path::new("output"), &[], None)?;

// Incremental OTA: provide old images directory
p.extract(Path::new("output"), &[], Some(Path::new("old")))?

// Export metadata as JSON
let meta = p.metadata_export();
println!("{}", serde_json::to_string_pretty(&meta)?);
```

## Acknowledgments

- Inspired by [payload-dumper](https://github.com/5ec1cff/payload-dumper) by [5ec1cff](https://github.com/5ec1cff)
- Original payload-dumper concept by [vm03](https://github.com/vm03/payload_dumper)
- Protobuf schema from [AOSP update_engine](https://android.googlesource.com/platform/system/update_engine/)

## License

[Apache-2.0](LICENSE)
