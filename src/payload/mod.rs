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
use serde::Serialize;

use proto::{DeltaArchiveManifest, InstallOperation, install_operation};

// ── Public API ──────────────────────────────────────────────────────────────

/// Information about a partition in the payload.
#[derive(Debug, Clone, Serialize)]
pub struct PartitionInfo {
    pub name: String,
    pub size_bytes: u64,
    pub num_operations: usize,
}

/// Dynamic partition group information from OTA manifest.
#[derive(Debug, Clone, Serialize)]
pub struct SuperGroupInfo {
    /// Group name, e.g. "main", "qti_dynamic_partitions"
    pub name: String,
    /// Maximum group size in bytes (0 if unspecified)
    pub max_size: u64,
    /// Partition names in this group
    pub partition_names: Vec<String>,
}

/// Comprehensive ROM information derived from payload manifest.
#[derive(Debug, Clone, Serialize)]
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

/// Per-partition detail for metadata export, including operation type breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct PartitionDetail {
    pub name: String,
    pub size: u64,
    pub size_human: String,
    pub num_operations: usize,
    pub operation_types: Vec<OpTypeCount>,
    pub is_differential: bool,
}

/// Operation type and count.
#[derive(Debug, Clone, Serialize)]
pub struct OpTypeCount {
    #[serde(rename = "type")]
    pub op_type: String,
    pub count: usize,
}

/// Comprehensive metadata export.
#[derive(Debug, Clone, Serialize)]
pub struct MetadataExport {
    pub payload_version: u64,
    pub block_size: u64,
    pub is_incremental: bool,
    pub max_timestamp: Option<i64>,
    pub security_patch_level: Option<String>,
    pub partial_update: bool,
    pub partitions: Vec<PartitionDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_partition_metadata: Option<DynPartMetaExport>,
}

/// Dynamic partition metadata for export.
#[derive(Debug, Clone, Serialize)]
pub struct DynPartMetaExport {
    pub snapshot_enabled: bool,
    pub vabc_enabled: bool,
    pub vabc_compression_param: Option<String>,
    pub cow_version: Option<u32>,
    pub groups: Vec<SuperGroupInfo>,
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

    /// Returns true if this is an incremental (differential) OTA.
    pub fn is_incremental(&self) -> bool {
        self.manifest.partitions.iter().any(|p| {
            p.operations.iter().any(|op| {
                matches!(
                    install_operation::Type::try_from(op.r#type),
                    Ok(install_operation::Type::SourceCopy)
                    | Ok(install_operation::Type::SourceBsdiff)
                    | Ok(install_operation::Type::BrotliBsdiff)
                    | Ok(install_operation::Type::Puffdiff)
                )
            })
        })
    }

    /// Export comprehensive metadata as a serializable structure.
    pub fn metadata_export(&self) -> MetadataExport {
        let partitions: Vec<PartitionDetail> = self.manifest.partitions.iter().map(|p| {
            let size: u64 = p.operations.iter()
                .flat_map(|op| &op.dst_extents)
                .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
                .sum();

            let mut type_counts = std::collections::BTreeMap::new();
            let mut has_diff = false;
            for op in &p.operations {
                let t = install_operation::Type::try_from(op.r#type)
                    .map(|t| format!("{t:?}"))
                    .unwrap_or_else(|_| format!("Unknown({})", op.r#type));
                if matches!(
                    install_operation::Type::try_from(op.r#type),
                    Ok(install_operation::Type::SourceCopy)
                    | Ok(install_operation::Type::SourceBsdiff)
                    | Ok(install_operation::Type::BrotliBsdiff)
                    | Ok(install_operation::Type::Puffdiff)
                ) {
                    has_diff = true;
                }
                *type_counts.entry(t).or_insert(0usize) += 1;
            }

            let operation_types: Vec<OpTypeCount> = type_counts.into_iter()
                .map(|(op_type, count)| OpTypeCount { op_type, count })
                .collect();

            PartitionDetail {
                name: p.partition_name.clone(),
                size,
                size_human: crate::human_size(size),
                num_operations: p.operations.len(),
                operation_types,
                is_differential: has_diff,
            }
        }).collect();

        let is_incremental = partitions.iter().any(|p| p.is_differential);

        let dpm = self.manifest.dynamic_partition_metadata.as_ref().map(|d| {
            DynPartMetaExport {
                snapshot_enabled: d.snapshot_enabled.unwrap_or(false),
                vabc_enabled: d.vabc_enabled.unwrap_or(false),
                vabc_compression_param: d.vabc_compression_param.clone(),
                cow_version: d.cow_version,
                groups: d.groups.iter().map(|g| SuperGroupInfo {
                    name: g.name.clone(),
                    max_size: g.size.unwrap_or(0),
                    partition_names: g.partition_names.clone(),
                }).collect(),
            }
        });

        MetadataExport {
            payload_version: 2,
            block_size: self.block_size,
            is_incremental,
            max_timestamp: self.manifest.max_timestamp,
            security_patch_level: self.manifest.security_patch_level.clone(),
            partial_update: self.manifest.partial_update.unwrap_or(false),
            partitions,
            dynamic_partition_metadata: dpm,
        }
    }

    /// Extract specific partitions (or all if `names` is empty) to `output_dir`.
    pub fn extract(
        &self,
        output_dir: &Path,
        names: &[String],
        source_dir: Option<&Path>,
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
            old_file: Option<File>,
            #[allow(dead_code)]
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

            // Open old partition image for incremental OTA
            let old_file = if let Some(sd) = source_dir {
                let old_path = sd.join(format!("{name}.img"));
                if old_path.exists() {
                    Some(File::open(&old_path)
                        .with_context(|| format!("open old image: {}", old_path.display()))?)
                } else {
                    None
                }
            } else {
                None
            };

            part_metas.push(PartMeta { name: name.clone(), out_file, old_file, total_size });

            for (oi, op) in part.operations.iter().enumerate() {
                all_ops.push((pi, oi, op));
            }
        }

        // reader 是 Arc<dyn ReadAt>，天然线程安全，直接共享引用。
        let src: &dyn ReadAt = self.reader.as_ref();

        // 跨所有分区、所有 operation 并行处理，最大化吞吐量。
        all_ops.par_iter().try_for_each(|&(pi, oi, op)| -> Result<()> {
            let meta = &part_metas[pi];
            self.apply_operation(src, &meta.out_file, op, meta.old_file.as_ref())
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
        old: Option<&File>,
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
                let old = old.ok_or_else(|| anyhow::anyhow!(
                    "SOURCE_COPY requires old partition image (use --source-dir)"))?;
                let src_data = self.read_src_extents(old, &op.src_extents)?;
                self.write_extents(out, &op.dst_extents, &src_data)?;
            }

            install_operation::Type::SourceBsdiff => {
                let old = old.ok_or_else(|| anyhow::anyhow!(
                    "SOURCE_BSDIFF requires old partition image (use --source-dir)"))?;
                let src_data = self.read_src_extents(old, &op.src_extents)?;
                let patch = data.as_deref()
                    .ok_or_else(|| anyhow::anyhow!("SOURCE_BSDIFF: no patch data"))?;
                let new_data = bsdiff_patch(&src_data, patch)?;
                self.write_extents(out, &op.dst_extents, &new_data)?;
            }

            install_operation::Type::BrotliBsdiff => {
                let old = old.ok_or_else(|| anyhow::anyhow!(
                    "BROTLI_BSDIFF requires old partition image (use --source-dir)"))?;
                let src_data = self.read_src_extents(old, &op.src_extents)?;
                let compressed = data.as_deref()
                    .ok_or_else(|| anyhow::anyhow!("BROTLI_BSDIFF: no data"))?;
                let patch = brotli_decompress(compressed)?;
                let new_data = bsdiff_patch(&src_data, &patch)?;
                self.write_extents(out, &op.dst_extents, &new_data)?;
            }

            install_operation::Type::Puffdiff => {
                bail!("PUFFDIFF is not yet supported (requires puffin library)");
            }

            other => {
                bail!("Unsupported operation type: {other:?}");
            }
        }

        Ok(())
    }

    /// Read blocks from an old partition image at specified source extents.
    fn read_src_extents(&self, old: &File, extents: &[proto::Extent]) -> Result<Vec<u8>> {
        let total: u64 = extents.iter()
            .map(|e| e.num_blocks.unwrap_or(0) * self.block_size)
            .sum();
        let mut data = vec![0u8; total as usize];
        let mut pos = 0usize;
        for ext in extents {
            let start = ext.start_block.unwrap_or(0) * self.block_size;
            let size = (ext.num_blocks.unwrap_or(0) * self.block_size) as usize;
            pread_exact(old, &mut data[pos..pos + size], start)
                .context("read old partition image")?;
            pos += size;
        }
        Ok(data)
    }

    /// Write data to output file at positions described by dst_extents, using pwrite.
    fn write_extents(
        &self,
        out: &File,
        extents: &[proto::Extent],
        data: &[u8],
    ) -> Result<()> {
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
            pwrite_all(out, &data[offset..end], start)?;
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

/// Decompress brotli data.
fn brotli_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut reader = brotli::Decompressor::new(data, 4096);
    std::io::Read::read_to_end(&mut reader, &mut output)
        .context("brotli decompression")?;
    Ok(output)
}

/// Apply a bsdiff patch (supports both BSDIFF40 and BSDF2 formats).
///
/// BSDIFF40: classic format with bzip2-compressed control/diff/extra blocks.
/// BSDF2: AOSP format supporting bzip2, brotli, or uncompressed blocks.
fn bsdiff_patch(old: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    if patch.len() < 32 {
        bail!("bsdiff patch too short ({} bytes)", patch.len());
    }

    #[derive(Clone, Copy)]
    enum Comp { Bz2, Brotli, Raw }

    let (comp, ctrl_len, diff_len, new_size) =
        if patch.len() >= 8 && &patch[0..8] == b"BSDIFF40" {
            (
                Comp::Bz2,
                bsdiff_off(&patch[8..]) as usize,
                bsdiff_off(&patch[16..]) as usize,
                bsdiff_off(&patch[24..]) as usize,
            )
        } else if patch.len() >= 6 && &patch[0..5] == b"BSDF2" {
            let c = match patch[5] {
                0 => Comp::Bz2,
                1 => Comp::Brotli,
                2 => Comp::Raw,
                other => bail!("BSDF2: unsupported compression type {other}"),
            };
            (
                c,
                bsdiff_off(&patch[8..]) as usize,
                bsdiff_off(&patch[16..]) as usize,
                bsdiff_off(&patch[24..]) as usize,
            )
        } else {
            bail!(
                "Unknown bsdiff format (magic: {:02x?})",
                &patch[..std::cmp::min(8, patch.len())]
            );
        };

    let ctrl_raw = &patch[32..32 + ctrl_len];
    let diff_raw = &patch[32 + ctrl_len..32 + ctrl_len + diff_len];
    let extra_raw = &patch[32 + ctrl_len + diff_len..];

    let decompress = |data: &[u8], c: Comp| -> Result<Vec<u8>> {
        match c {
            Comp::Bz2 => bzip2_decompress(data, data.len() * 4),
            Comp::Brotli => brotli_decompress(data),
            Comp::Raw => Ok(data.to_vec()),
        }
    };

    let ctrl = decompress(ctrl_raw, comp)?;
    let diff = decompress(diff_raw, comp)?;
    let extra = decompress(extra_raw, comp)?;

    let mut new = vec![0u8; new_size];
    let mut old_pos: i64 = 0;
    let mut new_pos = 0usize;
    let mut ctrl_pos = 0usize;
    let mut diff_pos = 0usize;
    let mut extra_pos = 0usize;

    while new_pos < new_size {
        if ctrl_pos + 24 > ctrl.len() {
            bail!("bsdiff: control block exhausted at new_pos={new_pos}/{new_size}");
        }

        let add = bsdiff_off(&ctrl[ctrl_pos..]) as usize;
        let copy = bsdiff_off(&ctrl[ctrl_pos + 8..]) as usize;
        let seek = bsdiff_off(&ctrl[ctrl_pos + 16..]);
        ctrl_pos += 24;

        // Add: new[i] = old[old_pos+i] + diff[diff_pos+i]
        if new_pos + add > new_size {
            bail!("bsdiff: add overflow ({add} at pos {new_pos}, size {new_size})");
        }
        if diff_pos + add > diff.len() {
            bail!("bsdiff: diff block too short");
        }
        for _ in 0..add {
            let ob = if old_pos >= 0 && (old_pos as usize) < old.len() {
                old[old_pos as usize]
            } else {
                0
            };
            new[new_pos] = ob.wrapping_add(diff[diff_pos]);
            new_pos += 1;
            diff_pos += 1;
            old_pos += 1;
        }

        // Copy from extra block
        if copy > 0 {
            if new_pos + copy > new_size || extra_pos + copy > extra.len() {
                bail!("bsdiff: extra block overflow");
            }
            new[new_pos..new_pos + copy]
                .copy_from_slice(&extra[extra_pos..extra_pos + copy]);
            new_pos += copy;
            extra_pos += copy;
        }

        old_pos += seek;
    }

    Ok(new)
}

/// Read a bsdiff-encoded offset: absolute value in bits 0–62, sign in bit 63.
fn bsdiff_off(buf: &[u8]) -> i64 {
    let raw = u64::from_le_bytes(buf[..8].try_into().unwrap());
    let abs = (raw & 0x7FFF_FFFF_FFFF_FFFF) as i64;
    if raw >> 63 != 0 { -abs } else { abs }
}

// ── Cross-platform positioned IO helpers ────────────────────────────────────

#[cfg(unix)]
fn pread_exact(f: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    FileExt::read_exact_at(f, buf, offset)
}

#[cfg(windows)]
fn pread_exact(f: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("unexpected EOF at offset {}", offset + done as u64),
            ));
        }
        done += n;
    }
    Ok(())
}

#[cfg(unix)]
fn pwrite_all(f: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    FileExt::write_all_at(f, buf, offset)
}

#[cfg(windows)]
fn pwrite_all(f: &File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_write(&buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write returned zero",
            ));
        }
        done += n;
    }
    Ok(())
}
