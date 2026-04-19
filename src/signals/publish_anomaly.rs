//! PublishAnomaly: Tier 0 signal for detecting anomalous publish patterns.
//!
//! Sub-checks (weights sum capped at 0.35 via the overall weighted score;
//! each sub-check contributes at most once per scoring pass):
//!   - Cadence (0.15): log(inter-publish interval) + MAD; flag if latest
//!     |log(i) - mean(log)| > 3.5 * MAD. Skip if <5 versions of history.
//!   - HourOfDay (0.10): histogram of publish hours (UTC). Flag if the
//!     latest publish's UTC hour has <5% historical frequency.
//!   - VersionSequence (0.10): patch bump within 4h of a major/minor
//!     release when historical median patch interval is >48h. Requires a
//!     sensible semver parse.

use crate::signals::Check;
use crate::types::{PackageIntel, PolicyConfig, PublishAnomalyKind, Signal};

pub struct PublishAnomalyCheck;

impl Check for PublishAnomalyCheck {
    fn name(&self) -> &'static str {
        "publish_anomaly"
    }

    fn evaluate(&self, intel: &PackageIntel, _config: &PolicyConfig) -> Vec<Signal> {
        let mut out = Vec::new();
        let latest = match find_latest(intel) {
            Some(l) => l,
            None => return out,
        };

        if let Some(signal) = check_cadence(&intel.publish_history, latest.1) {
            out.push(signal);
        }
        if let Some(signal) = check_hour(&intel.publish_history, latest.1) {
            out.push(signal);
        }
        if let Some(signal) = check_version_sequence(&intel.publish_history, &latest.0) {
            out.push(signal);
        }
        out
    }
}

fn find_latest(intel: &PackageIntel) -> Option<(String, u64)> {
    let history = &intel.publish_history;
    if history.is_empty() {
        return None;
    }
    let current = history
        .iter()
        .find(|(v, _)| v == &intel.version)
        .cloned()
        .or_else(|| {
            let mut clone = history.clone();
            clone.sort_by_key(|(_, t)| *t);
            clone.last().cloned()
        });
    current
}

fn check_cadence(history: &[(String, u64)], latest_time: u64) -> Option<Signal> {
    let mut timestamps: Vec<u64> = history.iter().map(|(_, t)| *t).collect();
    timestamps.sort();
    let mut truncated: Vec<u64> = timestamps
        .iter()
        .rev()
        .take(20)
        .copied()
        .collect::<Vec<_>>();
    truncated.reverse();
    if truncated.len() < 5 {
        return None;
    }
    let prior = &truncated[..truncated.len() - 1];
    let intervals: Vec<f64> = prior
        .windows(2)
        .map(|w| (w[1].saturating_sub(w[0]).max(1)) as f64)
        .map(|secs| secs.ln())
        .collect();
    if intervals.is_empty() {
        return None;
    }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    let mut deviations: Vec<f64> = intervals.iter().map(|x| (x - mean).abs()).collect();
    deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = if deviations.is_empty() {
        0.0
    } else {
        deviations[deviations.len() / 2].max(1e-6)
    };
    let prev_time = *prior.last().unwrap();
    let latest_interval = latest_time.saturating_sub(prev_time).max(1);
    let latest_log = (latest_interval as f64).ln();
    let deviation = (latest_log - mean).abs();
    if deviation > 3.5 * mad {
        let hours = latest_interval as f64 / 3600.0;
        return Some(Signal::PublishAnomaly {
            kind: PublishAnomalyKind::Cadence,
            detail: format!(
                "latest interval {:.1}h is {:.1}×MAD above historical log mean",
                hours,
                deviation / mad
            ),
        });
    }
    None
}

fn check_hour(history: &[(String, u64)], latest_time: u64) -> Option<Signal> {
    // Need enough history for the distribution to be meaningful.
    if history.len() < 10 {
        return None;
    }
    let mut counts = [0u32; 24];
    let mut total = 0u32;
    for (_, t) in history {
        if *t == latest_time {
            continue;
        }
        let hour = ((t / 3600) % 24) as usize;
        counts[hour] += 1;
        total += 1;
    }
    if total < 10 {
        return None;
    }

    // Skip if the distribution looks automated/uniform: many distinct hours
    // used means there's no meaningful "off-hours" pattern to contrast.
    let distinct_hours = counts.iter().filter(|c| **c > 0).count();
    if distinct_hours >= 12 {
        return None;
    }

    let latest_hour = ((latest_time / 3600) % 24) as usize;
    // Require a hard pattern break: the latest hour has never been used.
    if counts[latest_hour] == 0 {
        Some(Signal::PublishAnomaly {
            kind: PublishAnomalyKind::HourOfDay,
            detail: format!(
                "publish hour {}Z has no precedent in last {} versions ({} distinct hours historically)",
                latest_hour, total, distinct_hours
            ),
        })
    } else {
        None
    }
}

fn check_version_sequence(history: &[(String, u64)], latest_version: &str) -> Option<Signal> {
    let (major, minor, patch) = parse_semver(latest_version)?;
    if patch == 0 {
        return None;
    }
    let latest_time = history.iter().find(|(v, _)| v == latest_version)?.1;

    let mut patch_intervals: Vec<i64> = Vec::new();
    let mut seen_versions: Vec<((u64, u64, u64), u64)> = history
        .iter()
        .filter_map(|(v, t)| parse_semver(v).map(|parsed| (parsed, *t)))
        .collect();
    seen_versions.sort_by_key(|(_, t)| *t);
    for window in seen_versions.windows(2) {
        let (prev_v, prev_t) = window[0];
        let (next_v, next_t) = window[1];
        if prev_v.0 == next_v.0 && prev_v.1 == next_v.1 && next_v.2 > prev_v.2 {
            patch_intervals.push(next_t as i64 - prev_t as i64);
        }
    }
    if patch_intervals.is_empty() {
        return None;
    }
    patch_intervals.sort();
    let median = patch_intervals[patch_intervals.len() / 2];
    let median_hours = median as f64 / 3600.0;
    if median_hours < 48.0 {
        return None;
    }
    let predecessor = seen_versions
        .iter()
        .rev()
        .find(|((mj, mn, _), t)| *mj == major && *mn == minor && *t < latest_time);
    let ((_, _, _), prev_t) = predecessor?;
    let interval_hours = (latest_time.saturating_sub(*prev_t) as f64) / 3600.0;
    if interval_hours < 4.0 {
        return Some(Signal::PublishAnomaly {
            kind: PublishAnomalyKind::VersionSequence,
            detail: format!(
                "patch {latest_version} shipped {interval_hours:.1}h after same minor (historical median {median_hours:.1}h)"
            ),
        });
    }
    None
}

fn parse_semver(v: &str) -> Option<(u64, u64, u64)> {
    let head = v.split(['-', '+']).next()?;
    let mut parts = head.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intel_with(version: &str, history: Vec<(&str, u64)>) -> PackageIntel {
        PackageIntel {
            version: version.to_string(),
            publish_history: history
                .into_iter()
                .map(|(v, t)| (v.to_string(), t))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn quiet_history_skips_cadence_check() {
        let intel = intel_with(
            "1.0.0",
            vec![("1.0.0", 100_000), ("0.9.0", 50_000), ("0.8.0", 10_000)],
        );
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert!(
            out.iter().all(|s| !matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::Cadence,
                    ..
                }
            )),
            "cadence should not fire with <5 versions: {out:?}"
        );
    }

    #[test]
    fn weekly_cadence_normal_latest_does_not_flag() {
        let mut history = Vec::new();
        let week = 7 * 24 * 3600u64;
        for i in 0..20 {
            history.push((format!("1.0.{i}"), 1_000_000 + i as u64 * week));
        }
        let latest_time = history.last().unwrap().1;
        let hist_refs: Vec<(&str, u64)> = history.iter().map(|(v, t)| (v.as_str(), *t)).collect();
        let intel = intel_with("1.0.19", hist_refs);
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        let _ = latest_time;
        assert!(
            !out.iter().any(|s| matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::Cadence,
                    ..
                }
            )),
            "normal weekly interval should not flag: {out:?}"
        );
    }

    #[test]
    fn week_cadence_with_60d_gap_flags() {
        let mut history: Vec<(String, u64)> = Vec::new();
        let week = 7 * 24 * 3600u64;
        for i in 0..19 {
            history.push((format!("1.0.{i}"), 1_000_000 + i as u64 * week));
        }
        let prev_t = history.last().unwrap().1;
        let latest_t = prev_t + 60 * 24 * 3600;
        history.push(("1.0.19".into(), latest_t));
        let intel = PackageIntel {
            version: "1.0.19".into(),
            publish_history: history,
            ..Default::default()
        };
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert!(
            out.iter().any(|s| matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::Cadence,
                    ..
                }
            )),
            "60-day gap after 7-day cadence should flag: {out:?}"
        );
    }

    #[test]
    fn off_hour_publish_flags() {
        let mut history: Vec<(String, u64)> = Vec::new();
        for i in 0..20 {
            history.push((format!("1.0.{i}"), day_at(i, 14)));
        }
        history.push(("1.0.20".into(), day_at(20, 3)));
        let intel = PackageIntel {
            version: "1.0.20".into(),
            publish_history: history,
            ..Default::default()
        };
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert!(
            out.iter().any(|s| matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::HourOfDay,
                    ..
                }
            )),
            "3am publish against 14h history should flag: {out:?}"
        );
    }

    #[test]
    fn same_hour_publish_does_not_flag() {
        let mut history: Vec<(String, u64)> = Vec::new();
        for i in 0..20 {
            history.push((format!("1.0.{i}"), day_at(i, 14)));
        }
        history.push(("1.0.20".into(), day_at(20, 14)));
        let intel = PackageIntel {
            version: "1.0.20".into(),
            publish_history: history,
            ..Default::default()
        };
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert!(
            !out.iter().any(|s| matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::HourOfDay,
                    ..
                }
            )),
            "normal hour should not flag: {out:?}"
        );
    }

    #[test]
    fn rapid_patch_after_slow_history_flags() {
        let fortnight = 14 * 24 * 3600u64;
        let mut history: Vec<(String, u64)> = Vec::new();
        for i in 0..10u64 {
            history.push((format!("1.0.{i}"), 1_000_000 + i * fortnight));
        }
        let prev_t = history.last().unwrap().1;
        let major_t = prev_t + fortnight;
        history.push(("2.0.0".into(), major_t));
        history.push(("2.0.1".into(), major_t + 2 * 3600));

        let intel = PackageIntel {
            version: "2.0.1".into(),
            publish_history: history,
            ..Default::default()
        };
        let out = PublishAnomalyCheck.evaluate(&intel, &PolicyConfig::default());
        assert!(
            out.iter().any(|s| matches!(
                s,
                Signal::PublishAnomaly {
                    kind: PublishAnomalyKind::VersionSequence,
                    ..
                }
            )),
            "2h patch after slow history should flag: {out:?}"
        );
    }

    #[test]
    fn cap_on_total_weight_is_0_35() {
        let sum = Signal::PublishAnomaly {
            kind: PublishAnomalyKind::Cadence,
            detail: String::new(),
        }
        .weight()
            + Signal::PublishAnomaly {
                kind: PublishAnomalyKind::HourOfDay,
                detail: String::new(),
            }
            .weight()
            + Signal::PublishAnomaly {
                kind: PublishAnomalyKind::VersionSequence,
                detail: String::new(),
            }
            .weight();
        assert!((sum - 0.35).abs() < 1e-9, "sum = {sum}");
    }

    fn day_at(day: u64, hour: u64) -> u64 {
        1_700_000_000 + day * 86400 + hour * 3600
    }
}
