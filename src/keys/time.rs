use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// `YYYY-MM-DD` for the current UTC day. Computed via days-since-epoch
/// arithmetic so we don't depend on the host `date` binary or pull in a
/// time crate.
pub fn today() -> Result<String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_secs();
    Ok(format_ymd(secs / 86_400))
}

fn format_ymd(days_since_epoch: u64) -> String {
    let (y, m, d) = ymd_from_days(days_since_epoch);
    format!("{y:04}-{m:02}-{d:02}")
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Convert days-since-1970-01-01 (UTC) into a (year, month, day) triple.
/// Walks year-by-year then month-by-month — fine for our scale (one call
/// per process startup), and avoids a chrono-style table dep.
fn ymd_from_days(mut days: u64) -> (i64, u32, u32) {
    let mut y: i64 = 1970;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if days < year_days {
            break;
        }
        days -= year_days;
        y += 1;
    }
    let mut m: u32 = 0;
    loop {
        let mut md = DAYS_IN_MONTH[m as usize] as u64;
        if m == 1 && is_leap(y) {
            md = 29;
        }
        if days < md {
            break;
        }
        days -= md;
        m += 1;
    }
    (y, m + 1, days as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_day_is_1970_01_01() {
        assert_eq!(format_ymd(0), "1970-01-01");
    }

    #[test]
    fn handles_leap_year() {
        // 2024-02-29 is day 19_782 since epoch.
        assert_eq!(format_ymd(19_782), "2024-02-29");
        assert_eq!(format_ymd(19_783), "2024-03-01");
    }

    #[test]
    fn handles_century_non_leap() {
        // 2100 is not a leap year (divisible by 100, not by 400).
        // 2100-02-28 is day 47_540; 2100-03-01 is day 47_541.
        assert_eq!(format_ymd(47_540), "2100-02-28");
        assert_eq!(format_ymd(47_541), "2100-03-01");
    }

    #[test]
    fn handles_400_leap() {
        // 2000-02-29 is day 11_016 since epoch.
        assert_eq!(format_ymd(11_016), "2000-02-29");
    }
}
