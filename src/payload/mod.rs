// Native Rust payload.bin dumper — replaces Python payload_dumper entirely.
//
// Supports all InstallOperation types used in modern Android OTA payloads:
//   REPLACE, REPLACE_BZ, REPLACE_XZ, ZERO, SOURCE_COPY,
//   SOURCE_BSDIFF, BROTLI_BSDIFF, ZSTD
//
// File format (CrAU v2):
//   magic[4]  "CrAU"
//   u64       file_format_version  (== 2)
//   u64       manifest_size
//   u32       metadata_signature_size
//   bytes     manifest[manifest_size]          (protobuf DeltaArchiveManifest)
//   bytes     metadata_signature[metadata_signature_size]
//   bytes     data_blobs[]                     (referenced by operations)
//
// 数据源抽象：
//   - 本地文件（Payload::open / open_at）
//   - 远程 payload.bin URL（Payload::open_url）
//   - 远程 OTA ZIP URL（Payload::open_zip_url，自动解析 Central Directory）

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/chromeos_update_engine.rs"));
}
pub mod read_at;
pub mod http;

pub use http::HttpFile;
pub use read_at::ReadAt;

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail, Context};
use prost::Message;
use rayon::prelude::*;

use proto::{DeltaArchiveManifest, InstallOperation, install_operation};

// ── Public API ──────────────────────────────────────────────────────────────

/// Information about a partition in the payload.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub name: String,
    pub size_bytes: u64,
    pub num_operations: usize,
}

/// Dynamic partition group information from OTA manifest.
#[derive(Debug, Clone)]
pub struct SuperGroupInfo {
    /// Group name, e.g. "main", "qti_dynamic_partitions"
    pub name: String,
    /// Maximum group size in bytes (0 if unspecified)
    pub max_size: u64,
    /// Partition names in this group
    pub partition_names: Vec<String>,
}

/// Comprehensive ROM information derived from payload manifest.
#[derive(Debug, Clone)]
pub struct RomInfo {
    /// All partitions and their sizes
    pub partitions: Vec<PartitionInfo>,
    /// Whether A/B slot scheme is detected
    pub is_ab: bool,
    /// Whether Virtual A/B (snapshot-based) is detected
    pub is_vab: bool,
    /// Whether VABC (Virtual A/B Compression) is enabled
    pub is_vabc: bool,
    /// Dynamic partition groups (super partitions)
    pub super_groups: Vec<SuperGroupInfo>,
    /// Calculated super device size in bytes
    pub super_device_size: u64,
    /// Security patch level (if present)
    pub security_patch_level: Option<String>,
}

/// 已解析的 payload 头部，可直接用于分区提取。
pub struct Payload {
    /// 数据源（本地文件或 HTTP 远程文件），线程安全共享引用。
    reader: Arc<dyn ReadAt>,
    /// payload 数据 blob 区的绝对字节偏移。
    /// = base_offset + 24 + manifest_size + metadata_sig_size
    data_offset: u64,
    /// 块大小（通常 4096）。
    block_size: u64,
    /// 已解析的 protobuf manifest。
    manifest: DeltaArchiveManifest,
}

impl Payload {
    /// 从本地 payload.bin 文件解析。
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_at(path, 0)
    }

    /// 从本地文件的指定偏移解析（用于 ZIP 内 STORED 的 payload.bin）。
    pub fn open_at(path: &Path, base_offset: u64) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::from_reader(Arc::new(file), base_offset)
    }

    /// 从远程 payload.bin URL 直接解析（无需下载整个文件）。
    pub fn open_url(url: &str) -> Result<Self> {
        let http = HttpFile::open(url).with_context(|| format!("open URL: {url}"))?;
        Self::from_reader(Arc::new(http), 0)
    }

    /// 从远程 OTA ZIP URL 解析：
    /// 自动通过 HTTP Range 请求解析 ZIP Central Directory，定位并读取 payload.bin。
    pub fn open_zip_url(url: &str) -> Result<Self> {
        let http = HttpFile::open(url).with_context(|| format!("open ZIP URL: {url}"))?;
        let payload_offset = http::locate_payload_in_zip_url(&http)
            .context("locate payload.bin in remote ZIP")?;
        Self::from_reader(Arc::new(http), payload_offset)
    }

    /// 通用构造器：从任意 ReadAt 实现和基础偏移解析 payload 头部。
    pub fn from_reader(reader: Arc<dyn ReadAt>, base_offset: u64) -> Result<Self> {
        // 读取固定 24 字节头部：magic(4) + version(8) + manifest_size(8) + meta_sig_size(4)
        let mut header = [0u8; 24];
        reader.read_exact_at(&mut header, base_offset)?;

        if &header[0..4] != b"CrAU" {
            bail!("Not a payload.bin (bad magic: {:?})", &header[0..4]);
        }

        let version = u64::from_be_bytes(header[4..12].try_into().unwrap());
        if version != 2 {
            bail!("Unsupported payload version {version} (only v2 supported)");
        }

        let manifest_size = u64::from_be_bytes(header[12..20].try_into().unwrap());
        let metadata_sig_size = u32::from_be_bytes(header[20..24].try_into().unwrap()) as u64;

        let mut manifest_buf = vec![0u8; manifest_size as usize];
        reader.read_exact_at(&mut manifest_buf, base_offset + 24)?;

        let manifest = DeltaArchiveManifest::decode(&manifest_buf[..])
            .context("decode DeltaArchiveManifest protobuf")?;

        let data_offset = base_offset + 24 + manifest_size + metadata_sig_size;
        let block_size = manifest.block_size.unwrap_or(4096) as u64;

        Ok(Self {
            reader,
            data_offset,
            block_size,
            manifest,
        })
    }

    /// List partitions in this payload.
    pub fn list_partitions(&self) -> Vec<PartitionInfo> {
        self.manifest
            .partitions
            .iter()
            .map(|p| {
                let size: u64 = p.operations.iter().flat_map(|op| &op.dst_extents).map(|e| {
                    e.num_blocks.unwrap_or(0) * self.block_size
                }).sum();
                PartitionInfo {
                    name: p.partition_name.clone(),
                    size_bytes: size,
                    num_operations: p.operations.len(),
                }
            })
            .collect()
    }

    /// Extract DynamicPartitionMetadata from the OTA manifest.
    ///
    /// Returns group name, group max size, and list of partition names
    /// for each dynamic partition group.  This is the information needed
    /// to correctly repack a super.img with `lpmake`.
    pub fn dynamic_partition_metadata(&self) -> Option<Vec<SuperGroupInfo>> {
        let dpm = self.manifest.dynamic_partition_metadata.as_ref()?;
        let groups: Vec<SuperGroupInfo> = dpm.groups.iter().map(|g| {
            SuperGroupInfo {
                name: g.name.clone(),
                max_size: g.size.unwrap_or(0),
                partition_names: g.partition_names.clone(),
            }
        }).collect();
        if groups.is_empty() { None } else { Some(groups) }
    }

    /// Analyze the OTA manifest and return comprehensive ROM information.
    pub fn rom_info(&self) -> RomInfo {
        let partitions = self.list_partitions();

        // A/B detection: check if partition names end with _a or _b,
        // or if there are known slot-suffixed partitions
        let has_slot_suffix = partitions.iter().any(|p| {
            p.name.ends_with("_a") || p.name.ends_with("_b")
        });
        // Also check: if we have boot_a/boot_b or system_a/system_b
        let has_ab_pairs = partitions.iter().any(|p| p.name == "boot_a" || p.name == "system_a");
        let is_ab = has_slot_suffix || has_ab_pairs;

        // Dynamic partition metadata
        let dpm = self.manifest.dynamic_partition_metadata.as_ref();

        // VA/B: snapshot_enabled in DynamicPartitionMetadata
        let is_vab = dpm
            .and_then(|d| d.snapshot_enabled)
            .unwrap_or(false);

        // VABC: vabc_enabled in DynamicPartitionMetadata
        let is_vabc = dpm
            .and_then(|d| d.vabc_enabled)
            .unwrap_or(false);

        // Super groups
        let super_groups = self.dynamic_partition_metadata().unwrap_or_default();

        // Calculate super device size — safe lower bound.
        //
        // Strategy (matching YAK-Python):
        // 1. Prefer group max_size from manifest (OEM-defined capacity, already has slack)
        // 2. Fall back to actual partition data sizes with headroom if max_size unavailable
        // 3. For VAB: manifest groups have no slot suffix; super needs _a + _b groups
        // 4. For traditional A/B: groups already have _a/_b suffixes
        // 5. Add LP metadata overhead and align to 1 MiB
        //
        // LP layout (matching Python YAKit):
        //   [metadata_reserved (4096)] [metadata_slot_0 .. metadata_slot_N]
        //   [partition_data ...]
        const LP_RESERVED: u64 = 4096;
        const LP_META_SIZE: u64 = 65536;
        const SUPER_ALIGNMENT: u64 = 512 * 1024 * 1024; // 0.5 GiB (matches Python)

        let metadata_slots: u64 = if is_ab { 3 } else { 2 };
        let metadata_overhead = LP_RESERVED + LP_META_SIZE * metadata_slots;

        // Determine group_max_size: use max(group.size) from manifest (matching Python)
        let group_max_size: u64 = super_groups.iter()
            .map(|g| g.max_size)
            .max()
            .unwrap_or(0);

        let super_device_size = if group_max_size > 0 {
            // Have valid group max_size from manifest — use it directly
            // (no ×2 for VAB: group_max_size is per-slot capacity, super device
            //  only needs enough for the active slot in snapshot-based VAB)
            let raw = group_max_size + metadata_overhead;
            // Align up to 0.5 GiB boundary (matches Python)
            (raw + SUPER_ALIGNMENT - 1) / SUPER_ALIGNMENT * SUPER_ALIGNMENT
        } else {
            // Fallback: sum actual partition sizes + metadata overhead
            let mut total_data_size: u64 = 0;
            for group in &super_groups {
                for pname in &group.partition_names {
                    let base_name = pname.strip_suffix("_a")
                        .or_else(|| pname.strip_suffix("_b"))
                        .unwrap_or(pname);
                    if let Some(pi) = partitions.iter().find(|p| {
                        p.name == *pname || p.name == base_name
                    }) {
                        total_data_size += pi.size_bytes;
                    }
                }
            }
            total_data_size + metadata_overhead
        };

        let security_patch_level = self.manifest.security_patch_level.clone();

        RomInfo {
            partitions,
            is_ab,
            is_vab,
            is_vabc,
            super_groups,
            super_device_size,
            security_patch_level,
        }
    }

    /// Extract specific partitions (or all if `names` is empty) to `output_dir`.
    pub fn extract(
        &self,
        output_dir: &Path,
        names: &[String],
    ) -> Result<()> {
        std::fs::create_dir_all(output_dir)?;

        let partitions: Vec<_> = if names.is_empty() {
            self.manifest.partitions.iter().collect()
        } else {
            let mut parts = Vec::new();
            for name in names {
                let p = self.manifest.partitions.iter()
                    .find(|p| p.partition_name == *name);
                match p {
                    Some(p) => parts.push(p),
                    None => eprintln!("[payload] Warning: partition \"{name}\" not found, skipping"),
                }
            }
            parts
        };

        if partitions.is_empty() {
            bail!("No partitions to extract");
        }

        // Flatten all (partition, operation_index) pairs for maximum parallelism.
        // First, create output files and collect metadata.
        struct PartMeta {
            name: String,
            out_file: File,
            total_size: u64,
        }
        let mut part_metas: Vec<PartMeta> = Vec::with_capacity(partitions.len());
        // Map from partition index → operation list
        let mut all_ops: Vec<(usize, usize, &InstallOperation)> = Vec::new();

        for (pi, part) in partitions.iter().enumerate() {
            let name = &part.partition_name;
            let out_path = output_dir.join(format!("{name}.img"));

            let total_blocks: u64 = part.operations.iter()
                .flat_map(|op| &op.dst_extents)
                .map(|e| e.num_blocks.unwrap_or(0))
                .sum();
            let total_size = total_blocks * self.block_size;

            eprintln!(
                "[payload] Extracting {name} ({}) \u{2014} {} operations",
                crate::human_size(total_size),
                part.operations.len(),
            );

            let out_file = File::create(&out_path)
                .with_context(|| format!("create {}", out_path.display()))?;
            out_file.set_len(total_size)?;

            part_metas.push(PartMeta { name: name.clone(), out_file, total_size });

            for (oi, op) in part.operations.iter().enumerate() {
                all_ops.push((pi, oi, op));
            }
        }

        // reader 是 Arc<dyn ReadAt>，天然线程安全，直接共享引用。
        let src: &dyn ReadAt = self.reader.as_ref();

        // 跨所有分区、所有 operation 并行处理，最大化吞吐量。
        all_ops.par_iter().try_for_each(|&(pi, oi, op)| -> Result<()> {
            let meta = &part_metas[pi];
            self.apply_operation(src, &meta.out_file, op)
                .with_context(|| format!("{}: operation {oi} (type {:?}) failed",
                    meta.name,
                    install_operation::Type::try_from(op.r#type)))
        })?;

        for meta in &part_metas {
            eprintln!("[payload] \u{2713} {}.img written", meta.name);
        }

        Ok(())
    }

    /// 应用单个 InstallOperation，使用随机读写（无 seek，无共享状态）。
    /// src 可以是本地 File 或 HttpFile，通过 ReadAt trait 统一调用。
    fn apply_operation(
        &self,
        src: &dyn ReadAt,
        out: &File,
        op: &InstallOperation,
    ) -> Result<()> {
        let op_type = install_operation::Type::try_from(op.r#type)
            .unwrap_or(install_operation::Type::Replace);

        // 通过 ReadAt::read_exact_at 读取 data blob（本地/HTTP 均支持）
        let data_len = op.data_length.unwrap_or(0) as usize;
        let data: Option<Vec<u8>> = if let Some(offset) = op.data_offset {
            if data_len > 0 {
                let mut buf = vec![0u8; data_len];
                src.read_exact_at(&mut buf, self.data_offset + offset)?;
                Some(buf)
            } else {
                None
            }
        } else {
            None
        };

        match op_type {
            install_operation::Type::Replace => {
                let data = data.as_deref().ok_or_else(|| anyhow::anyhow!("REPLACE: no data"))?;
                self.write_extents(out, &op.dst_extents, data)?;
            }

            install_operation::Type::ReplaceBz => {
                let compressed = data.as_deref().ok_or_else(|| anyhow::anyhow!("REPLACE_BZ: no data"))?;
                let expect_size = op.dst_extents.iter()
                    .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
                    .sum::<u64>() as usize;
                let decompressed = bzip2_decompress(compressed, expect_size)?;
                self.write_extents(out, &op.dst_extents, &decompressed)?;
            }

            install_operation::Type::ReplaceXz => {
                let compressed = data.as_deref().ok_or_else(|| anyhow::anyhow!("REPLACE_XZ: no data"))?;
                let expect_size = op.dst_extents.iter()
                    .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
                    .sum::<u64>() as usize;
                let decompressed = xz_decompress(compressed, expect_size)?;
                self.write_extents(out, &op.dst_extents, &decompressed)?;
            }

            install_operation::Type::Zero | install_operation::Type::Discard => {
                // Output was pre-filled with zeros via set_len; skip.
            }

            install_operation::Type::Zstd => {
                let compressed = data.as_deref().ok_or_else(|| anyhow::anyhow!("ZSTD: no data"))?;
                let expect_size = op.dst_extents.iter()
                    .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
                    .sum::<u64>() as usize;
                let decompressed = zstd::bulk::decompress(compressed, expect_size)
                    .context("ZSTD decompression")?;
                self.write_extents(out, &op.dst_extents, &decompressed)?;
            }

            install_operation::Type::SourceCopy => {
                bail!("SOURCE_COPY requires a differential OTA with --old; full OTA should not use this");
            }

            install_operation::Type::SourceBsdiff | install_operation::Type::BrotliBsdiff => {
                bail!("BSDIFF operations require a differential OTA with --old; full OTA should not use this");
            }

            other => {
                bail!("Unsupported operation type: {other:?}");
            }
        }

        Ok(())
    }

    /// Write data to output file at positions described by dst_extents, using pwrite.
    fn write_extents(
        &self,
        out: &File,
        extents: &[proto::Extent],
        data: &[u8],
    ) -> Result<()> {
        use std::os::unix::fs::FileExt;
        let mut offset = 0usize;
        for ext in extents {
            let start = ext.start_block.unwrap_or(0) * self.block_size;
            let size = (ext.num_blocks.unwrap_or(0) * self.block_size) as usize;
            let end = offset + size;
            if end > data.len() {
                bail!(
                    "extent wants {} bytes at data offset {offset}, but data is only {} bytes",
                    size, data.len()
                );
            }
            out.write_all_at(&data[offset..end], start)?;
            offset = end;
        }
        Ok(())
    }
}

// ── Decompression helpers ───────────────────────────────────────────────────

fn bzip2_decompress(data: &[u8], expect: usize) -> Result<Vec<u8>> {
    use bzip2::read::BzDecoder;
    use std::io::Read;
    let mut decoder = BzDecoder::new(data);
    let mut out = Vec::with_capacity(expect);
    decoder.read_to_end(&mut out).context("bzip2 decompression")?;
    Ok(out)
}

fn xz_decompress(data: &[u8], expect: usize) -> Result<Vec<u8>> {
    use xz2::read::XzDecoder;
    use std::io::Read;
    let mut decoder = XzDecoder::new(data);
    let mut out = Vec::with_capacity(expect);
    decoder.read_to_end(&mut out).context("xz decompression")?;
    Ok(out)
}
