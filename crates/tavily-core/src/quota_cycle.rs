//! Upstream monthly quota cycle math (ISSUE-0014).
//!
//! Tavily resets account credits on the **first day of each month**,
//! calendar-based, regardless of billing date (help.tavily.com "Understanding
//! API Credits Reset"; docs.tavily.com FAQ). A key that hit 432/433 must stay
//! frozen until that reset instead of retrying on a fixed 12h cadence.
//!
//! The exact reset timezone is not published, so we freeze until
//! `1st 00:00 UTC + 14h`: the latest plausible local-midnight reset is
//! UTC-12 (1st 12:00 UTC), leaving a 2h safety margin. Waking slightly late
//! costs at most a few hours of the fresh monthly quota; waking early would
//! burn a guaranteed 432 and re-freeze for a whole month.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Buffer after the 1st 00:00 UTC before the monthly reset is trusted.
pub const RESET_UTC_BUFFER_SECS: u64 = 14 * 3600;

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's
/// `civil_from_days` (proleptic Gregorian, era-aware, no branching bugs).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// (year, month, day) → days since 1970-01-01. Inverse of
/// [`civil_from_days`] (Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The monthly reset that starts the month containing `unix_secs`:
/// its 1st day at 00:00 UTC + [`RESET_UTC_BUFFER_SECS`], as unix seconds.
fn month_reset_after_shift(unix_secs: u64, month_shift: i32) -> u64 {
    let days = (unix_secs / 86400) as i64;
    let (y, m, _) = civil_from_days(days);
    // Shift the month, carrying into the next/previous year.
    let total = m as i32 - 1 + month_shift;
    let y = y + i64::from(total.div_euclid(12));
    let m = total.rem_euclid(12) as u32 + 1;
    let days = days_from_civil(y, m, 1);
    (days as u64) * 86400 + RESET_UTC_BUFFER_SECS
}

/// The first monthly reset **strictly after** `now`.
///
/// Same-day 14:00Z counts as already passed → the deadline rolls to the next
/// month. Cross-year (Dec → Jan) handled by the month carry.
pub fn next_monthly_reset(now: SystemTime) -> SystemTime {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut reset = month_reset_after_shift(secs, 0);
    if reset <= secs {
        reset = month_reset_after_shift(secs, 1);
    }
    UNIX_EPOCH + Duration::from_secs(reset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i64, m: u32, d: u32, h: u32, min: u32) -> SystemTime {
        UNIX_EPOCH
            + Duration::from_secs(
                days_from_civil(y, m, d) as u64 * 86400 + u64::from(h) * 3600 + u64::from(min) * 60,
            )
    }

    fn fmt(s: SystemTime) -> String {
        let secs = s.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let (y, m, d) = civil_from_days((secs / 86400) as i64);
        let tod = secs % 86400;
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}Z",
            tod / 3600,
            (tod % 3600) / 60
        )
    }

    #[test]
    fn mid_month_rolls_to_next_month_first() {
        // 2026-10-10 15:40Z (EXP-06 wall time) → 2026-11-01 14:00Z
        assert_eq!(
            fmt(next_monthly_reset(at(2026, 10, 10, 15, 40))),
            "2026-11-01 14:00Z"
        );
    }

    #[test]
    fn first_day_before_buffer_stays_same_day() {
        // 1st 13:00Z is before the 14:00Z deadline → same day.
        assert_eq!(
            fmt(next_monthly_reset(at(2026, 11, 1, 13, 0))),
            "2026-11-01 14:00Z"
        );
    }

    #[test]
    fn first_day_after_buffer_rolls_to_next_month() {
        // Exactly at / past the deadline → strictly-after semantics.
        assert_eq!(
            fmt(next_monthly_reset(at(2026, 11, 1, 14, 0))),
            "2026-12-01 14:00Z"
        );
        assert_eq!(
            fmt(next_monthly_reset(at(2026, 11, 1, 14, 1))),
            "2026-12-01 14:00Z"
        );
    }

    #[test]
    fn year_rollover_december_to_january() {
        assert_eq!(
            fmt(next_monthly_reset(at(2026, 12, 31, 23, 59))),
            "2027-01-01 14:00Z"
        );
    }

    #[test]
    fn february_boundary_leap_and_common() {
        // 2028 is a leap year: Feb has 29 days, but the 1st of March is what matters.
        assert_eq!(
            fmt(next_monthly_reset(at(2028, 2, 28, 8, 0))),
            "2028-03-01 14:00Z"
        );
        assert_eq!(
            fmt(next_monthly_reset(at(2027, 2, 10, 8, 0))),
            "2027-03-01 14:00Z"
        );
    }

    #[test]
    fn deadline_is_always_strictly_in_the_future() {
        for probe in [
            at(2026, 1, 1, 0, 0),
            at(2026, 6, 15, 12, 0),
            at(2030, 12, 1, 13, 59),
        ] {
            let reset = next_monthly_reset(probe);
            assert!(reset > probe);
            let secs = reset.duration_since(UNIX_EPOCH).unwrap().as_secs();
            let (y, m, d) = civil_from_days((secs / 86400) as i64);
            assert_eq!(d, 1, "reset must land on a month 1st: {y}-{m}-{d}");
            assert_eq!(secs % 86400, RESET_UTC_BUFFER_SECS, "reset at 14:00Z");
        }
    }
}
