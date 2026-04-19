// payload-dumper-rs library root
// Re-exports the payload module as the public API.

pub mod payload;

/// Human-readable file size string.
pub fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if val.fract() == 0.0 {
        format!("{} {}", val as u64, UNITS[unit])
    } else {
        format!("{:.1} {}", val, UNITS[unit])
    }
}
