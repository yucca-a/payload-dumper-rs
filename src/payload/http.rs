// payload::http — HTTP Range 请求 + 远程 ZIP 中央目录解析
//
// 允许直接从 URL 提取 payload.bin 分区，无需下载整个 OTA 包。
//
// 使用方式：
//   // 直接 payload.bin URL
//   let payload = Payload::open_url("https://.../payload.bin")?;
//   // OTA ZIP URL（自动解析 Central Directory 定位 payload.bin）
//   let payload = Payload::open_zip_url("https://.../ota.zip")?;

use anyhow::{bail, Context, Result};
use std::io::Read;

use super::read_at::ReadAt;

// ── ZIP 签名常量 ─────────────────────────────────────────────────────────────
const EOCD_SIG: u32 = 0x06054b50;
const EOCD64_SIG: u32 = 0x06064b50;
const EOCD64_LOC_SIG: u32 = 0x07064b50;
const CD_SIG: u32 = 0x02014b50;
const LFH_SIG: u32 = 0x04034b50;

// ── HttpFile ─────────────────────────────────────────────────────────────────

/// 通过 HTTP Range 请求实现随机访问的远程文件。
pub struct HttpFile {
    url: String,
    agent: ureq::Agent,
    pub size: u64,
}

impl HttpFile {
    /// 打开远程 URL，通过 HEAD 获取文件大小。
    pub fn open(url: &str) -> Result<Self> {
        let agent = ureq::agent();

        let resp = agent
            .head(url)
            .call()
            .with_context(|| format!("HEAD {url}"))?;

        let size = resp
            .header("content-length")
            .ok_or_else(|| anyhow::anyhow!("Server did not return Content-Length: {url}"))?
            .parse::<u64>()
            .context("parse Content-Length")?;

        eprintln!("[http] {url}: {} bytes", size);

        Ok(Self {
            url: url.to_string(),
            agent,
            size,
        })
    }

    /// 获取 [start, end] 闭区间字节范围。
    pub fn fetch_range(&self, start: u64, end: u64) -> Result<Vec<u8>> {
        let expected = (end - start + 1) as usize;
        let range_hdr = format!("bytes={start}-{end}");

        let resp = self
            .agent
            .get(&self.url)
            .set("Range", &range_hdr)
            .call()
            .with_context(|| format!("GET {range_hdr} {}", self.url))?;

        let mut buf = Vec::with_capacity(expected);
        resp.into_reader()
            .take((expected * 2) as u64) // 防止服务器返回额外数据
            .read_to_end(&mut buf)
            .context("reading HTTP response body")?;

        if buf.len() < expected {
            bail!(
                "Short read at {range_hdr}: expected {expected} bytes, got {}",
                buf.len()
            );
        }
        Ok(buf)
    }
}

impl ReadAt for HttpFile {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset + buf.len() as u64 - 1;
        let data = self.fetch_range(offset, end)?;
        buf.copy_from_slice(&data[..buf.len()]);
        Ok(())
    }

    fn size(&self) -> Option<u64> {
        Some(self.size)
    }
}

// ── 远程 ZIP 中央目录解析 ─────────────────────────────────────────────────────

/// 在远程 ZIP 文件中定位 `payload.bin` 的数据起始偏移量。
///
/// 流程：
/// 1. Range 请求末尾 ~65KB → 找到 EOCD（兼容 ZIP64）
/// 2. 获取 Central Directory
/// 3. 找到 payload.bin 条目的 Local File Header 偏移
/// 4. 读取 LFH 头，计算精确数据起始位置
pub fn locate_payload_in_zip_url(http: &HttpFile) -> Result<u64> {
    let file_size = http.size;

    // ── Step 1: 找 EOCD ──────────────────────────────────────────────────────
    // ZIP 注释最大 65535 字节，所以从末尾读 65556 字节足够找到 EOCD
    let search_len = std::cmp::min(65_556, file_size);
    let search_start = file_size - search_len;
    let tail = http.fetch_range(search_start, file_size - 1)?;

    let eocd_pos = find_sig_from_end(&tail, EOCD_SIG)
        .ok_or_else(|| anyhow::anyhow!("EOCD signature not found — not a valid ZIP"))?;

    // ── Step 2: ZIP64 判断 ──────────────────────────────────────────────────
    // ZIP64 EOCD Locator 固定在 EOCD 前 20 字节
    let (cd_offset, cd_size) =
        if eocd_pos >= 20 && read_u32_le(&tail[eocd_pos - 20..]) == EOCD64_LOC_SIG {
            // ZIP64 路径：从 locator 获取 ZIP64 EOCD 绝对偏移
            let zip64_eocd_abs = read_u64_le(&tail[eocd_pos - 20 + 8..]);

            // 读取 ZIP64 EOCD 记录（至少 56 字节）
            let z64 = http
                .fetch_range(zip64_eocd_abs, zip64_eocd_abs + 55)
                .context("fetch ZIP64 EOCD")?;

            if read_u32_le(&z64) != EOCD64_SIG {
                bail!("Invalid ZIP64 EOCD signature");
            }
            // ZIP64 EOCD 布局:
            //   sig(4) + record_size(8) + ver_made(2) + ver_needed(2)
            //   + disk_num(4) + disk_cd_start(4) + entries_on_disk(8) + total_entries(8)
            //   + cd_size(8) + cd_offset(8)
            let cd_size = read_u64_le(&z64[40..]);
            let cd_offset = read_u64_le(&z64[48..]);
            (cd_offset, cd_size)
        } else {
            // 标准 ZIP32 EOCD
            // 布局: sig(4) + disk(2) + start_disk(2) + entries_on_disk(2)
            //       + total_entries(2) + cd_size(4) + cd_offset(4) + comment_len(2)
            let eocd = &tail[eocd_pos..];
            let cd_size = read_u32_le(&eocd[12..]) as u64;
            let cd_offset = read_u32_le(&eocd[16..]) as u64;
            (cd_offset, cd_size)
        };

    eprintln!("[http] ZIP Central Directory: offset={cd_offset}, size={cd_size} bytes");

    // ── Step 3: 获取 Central Directory ─────────────────────────────────────
    let cd = http
        .fetch_range(cd_offset, cd_offset + cd_size - 1)
        .context("fetch Central Directory")?;

    // ── Step 4: 在 CD 中找 payload.bin 的 LFH 偏移 ─────────────────────────
    let lfh_offset = find_entry_in_cd(&cd, "payload.bin")
        .context("locate payload.bin in ZIP Central Directory")?;

    // ── Step 5: 读取 Local File Header → 计算数据起始位置 ──────────────────
    // LFH 固定部分 30 字节:
    //   sig(4) + ver_needed(2) + flags(2) + compression(2)
    //   + mod_time(2) + mod_date(2) + crc32(4) + comp_size(4) + uncomp_size(4)
    //   + fname_len(2) + extra_len(2)
    let lfh = http
        .fetch_range(lfh_offset, lfh_offset + 29)
        .context("fetch Local File Header")?;

    if read_u32_le(&lfh) != LFH_SIG {
        bail!(
            "Invalid Local File Header signature at offset {lfh_offset} (got 0x{:08x})",
            read_u32_le(&lfh)
        );
    }

    let fname_len = read_u16_le(&lfh[26..]) as u64;
    let extra_len = read_u16_le(&lfh[28..]) as u64;
    let data_start = lfh_offset + 30 + fname_len + extra_len;

    eprintln!("[http] payload.bin data starts at offset {data_start}");
    Ok(data_start)
}

// ── 内部工具函数 ──────────────────────────────────────────────────────────────

/// 从 buf 末尾向前搜索 4 字节小端签名，返回找到位置的索引。
fn find_sig_from_end(buf: &[u8], sig: u32) -> Option<usize> {
    let sig_bytes = sig.to_le_bytes();
    if buf.len() < 4 {
        return None;
    }
    for i in (0..=buf.len() - 4).rev() {
        if buf[i..i + 4] == sig_bytes {
            return Some(i);
        }
    }
    None
}

/// 在 Central Directory 数据中找到指定文件名的 LFH 绝对偏移。
fn find_entry_in_cd(cd: &[u8], name: &str) -> Result<u64> {
    let name_bytes = name.as_bytes();
    let mut pos = 0usize;

    while pos + 46 <= cd.len() {
        if read_u32_le(&cd[pos..]) != CD_SIG {
            bail!("Unexpected bytes in Central Directory at relative offset {pos}");
        }

        // CD 条目固定部分 46 字节:
        //   sig(4) + ver_made(2) + ver_needed(2) + flags(2) + compression(2)
        //   + mod_time(2) + mod_date(2) + crc32(4) + comp_size(4) + uncomp_size(4)
        //   + fname_len(2) + extra_len(2) + comment_len(2) + disk_start(2)
        //   + int_attrs(2) + ext_attrs(4) + lfh_offset(4)
        let fname_len = read_u16_le(&cd[pos + 28..]) as usize;
        let extra_len = read_u16_le(&cd[pos + 30..]) as usize;
        let comment_len = read_u16_le(&cd[pos + 32..]) as usize;

        if pos + 46 + fname_len > cd.len() {
            bail!("Central Directory entry truncated at offset {pos}");
        }

        let entry_name = &cd[pos + 46..pos + 46 + fname_len];
        if entry_name == name_bytes {
            // 找到！取 LFH 偏移（可能需要 ZIP64 扩展字段）
            let raw_lfh = read_u32_le(&cd[pos + 42..]) as u64;
            let lfh_offset = if raw_lfh == 0xFFFF_FFFF {
                // ZIP64：从 extra field 读取真实偏移
                let extra_start = pos + 46 + fname_len;
                let extra_end = extra_start + extra_len;
                if extra_end > cd.len() {
                    bail!("ZIP64 extra field out of bounds");
                }
                find_zip64_lfh_offset(&cd[extra_start..extra_end])?
            } else {
                raw_lfh
            };
            return Ok(lfh_offset);
        }

        pos += 46 + fname_len + extra_len + comment_len;
    }

    bail!("\"{}\" not found in ZIP Central Directory", name)
}

/// 从 ZIP64 扩展字段中提取 LFH 偏移。
///
/// ZIP64 扩展字段布局（只有对应主字段为 0xFFFFFFFF 时才包含）：
///   uncompressed_size(8) + compressed_size(8) + lfh_offset(8) + disk_start(4)
fn find_zip64_lfh_offset(extra: &[u8]) -> Result<u64> {
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let hdr_id = read_u16_le(&extra[i..]);
        let data_size = read_u16_le(&extra[i + 2..]) as usize;
        if hdr_id == 0x0001 {
            // ZIP64 Extended Information Extra Field (header id = 0x0001)
            // 前两个字段各 8 字节（uncomp + comp），第三个才是 lfh_offset
            if i + 4 + 24 <= extra.len() {
                return Ok(read_u64_le(&extra[i + 4 + 16..]));
            }
            bail!("ZIP64 extra field too short for LFH offset");
        }
        i += 4 + data_size;
    }
    bail!("ZIP64 LFH offset (header_id=0x0001) not found in extra field")
}

// ── 小端读取辅助 ─────────────────────────────────────────────────────────────

fn read_u16_le(buf: &[u8]) -> u16 {
    u16::from_le_bytes(buf[..2].try_into().unwrap())
}

fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf[..4].try_into().unwrap())
}

fn read_u64_le(buf: &[u8]) -> u64 {
    u64::from_le_bytes(buf[..8].try_into().unwrap())
}
