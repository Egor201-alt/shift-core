use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};

use crate::{Result, ShiftError, INNER_HEADER_LEN, MAX_BODY_LEN};

const WINDOW_SLOTS: usize = 5;
const MIN_WINDOW: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    InteractiveWeb,
    Burst,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SizeBucket {
    pub min_body: usize,
    pub max_body: usize,
    pub weight: u32,
}

#[derive(Clone, Debug)]
pub struct SizeProfile {
    buckets: Vec<SizeBucket>,
    total_weight: u32,
}

impl SizeProfile {
    pub fn new(buckets: Vec<SizeBucket>) -> Result<Self> {
        if buckets.is_empty() {
            return Err(ShiftError::InvalidConfig("size profile is empty"));
        }
        let mut total_weight = 0u32;
        for bucket in &buckets {
            if bucket.weight == 0 || bucket.min_body == 0 || bucket.min_body > bucket.max_body {
                return Err(ShiftError::InvalidConfig(
                    "size profile bucket is malformed",
                ));
            }
            if bucket.max_body > MAX_BODY_LEN {
                return Err(ShiftError::InvalidConfig(
                    "size profile exceeds the frame limit",
                ));
            }
            total_weight = total_weight
                .checked_add(bucket.weight)
                .ok_or(ShiftError::InvalidConfig("size profile weights overflow"))?;
        }
        Ok(SizeProfile {
            buckets,
            total_weight,
        })
    }

    pub fn https_default() -> Self {
        let buckets = vec![
            SizeBucket {
                min_body: 48,
                max_body: 120,
                weight: 28,
            },
            SizeBucket {
                min_body: 120,
                max_body: 320,
                weight: 22,
            },
            SizeBucket {
                min_body: 320,
                max_body: 700,
                weight: 18,
            },
            SizeBucket {
                min_body: 700,
                max_body: 1100,
                weight: 14,
            },
            SizeBucket {
                min_body: 1100,
                max_body: 1400,
                weight: 18,
            },
        ];
        SizeProfile {
            buckets,
            total_weight: 100,
        }
    }

    pub fn bounds(&self) -> (usize, usize) {
        let min = self.buckets.iter().map(|b| b.min_body).min().unwrap_or(0);
        let max = self.buckets.iter().map(|b| b.max_body).max().unwrap_or(0);
        (min, max)
    }

    pub fn sample(&self, rng: &mut fastrand::Rng) -> usize {
        let mut pick = rng.u32(0..self.total_weight);
        for bucket in &self.buckets {
            if pick < bucket.weight {
                return rng.usize(bucket.min_body..=bucket.max_body);
            }
            pick -= bucket.weight;
        }
        let last = self.buckets[self.buckets.len() - 1];
        last.max_body
    }
}

#[derive(Clone, Debug)]
pub struct ShaperConfig {
    pub burst_threshold_bytes: usize,
    pub window: Duration,
    pub burst_exit_percent: usize,
    pub min_padding: usize,
    pub max_padding: usize,
    pub burst_jitter_permille: u32,
    pub burst_jitter_max: usize,
    pub web_delay_permille: u32,
    pub web_delay_max: Duration,
    pub profile: SizeProfile,
}

impl Default for ShaperConfig {
    fn default() -> Self {
        ShaperConfig {
            burst_threshold_bytes: 64 * 1024,
            window: Duration::from_millis(250),
            burst_exit_percent: 25,
            min_padding: 16,
            max_padding: 128,
            burst_jitter_permille: 20,
            burst_jitter_max: 24,
            web_delay_permille: 150,
            web_delay_max: Duration::from_millis(6),
            profile: SizeProfile::https_default(),
        }
    }
}

impl ShaperConfig {
    pub fn validate(&self) -> Result<()> {
        if self.burst_threshold_bytes == 0 {
            return Err(ShiftError::InvalidConfig(
                "burst threshold must be positive",
            ));
        }
        if self.window < MIN_WINDOW {
            return Err(ShiftError::InvalidConfig("window is shorter than 10 ms"));
        }
        if self.burst_exit_percent == 0 || self.burst_exit_percent > 100 {
            return Err(ShiftError::InvalidConfig(
                "burst exit percent must be in 1..=100",
            ));
        }
        if self.min_padding == 0 || self.min_padding > self.max_padding {
            return Err(ShiftError::InvalidConfig("padding range is invalid"));
        }
        if self.burst_jitter_permille > 1000 || self.web_delay_permille > 1000 {
            return Err(ShiftError::InvalidConfig("permille value above 1000"));
        }
        if self.burst_jitter_max == 0 || self.burst_jitter_max > 1024 {
            return Err(ShiftError::InvalidConfig(
                "burst jitter must be in 1..=1024",
            ));
        }
        let (min_body, max_body) = self.profile.bounds();
        if min_body < INNER_HEADER_LEN + self.min_padding + 1 {
            return Err(ShiftError::InvalidConfig(
                "profile has bodies too small for min padding",
            ));
        }
        let widest_padding = self.max_padding - self.min_padding;
        if max_body + widest_padding > MAX_BODY_LEN {
            return Err(ShiftError::InvalidConfig(
                "profile plus padding exceeds the frame limit",
            ));
        }
        Ok(())
    }
}

struct SlidingWindow {
    slots: [usize; WINDOW_SLOTS],
    head: usize,
    head_start: Instant,
    slot_width: Duration,
    total: usize,
}

impl SlidingWindow {
    fn new(window: Duration, now: Instant) -> Self {
        SlidingWindow {
            slots: [0; WINDOW_SLOTS],
            head: 0,
            head_start: now,
            slot_width: window / WINDOW_SLOTS as u32,
            total: 0,
        }
    }

    fn advance(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.head_start);
        let steps = (elapsed.as_nanos() / self.slot_width.as_nanos()) as usize;
        if steps == 0 {
            return;
        }
        if steps >= WINDOW_SLOTS {
            self.slots = [0; WINDOW_SLOTS];
            self.total = 0;
            self.head_start = now;
            return;
        }
        for _ in 0..steps {
            self.head = (self.head + 1) % WINDOW_SLOTS;
            self.total = self.total.saturating_sub(self.slots[self.head]);
            self.slots[self.head] = 0;
        }
        self.head_start += self.slot_width * steps as u32;
    }

    fn record(&mut self, now: Instant, bytes: usize) {
        self.advance(now);
        self.slots[self.head] = self.slots[self.head].saturating_add(bytes);
        self.total = self.total.saturating_add(bytes);
    }

    fn total(&mut self, now: Instant) -> usize {
        self.advance(now);
        self.total
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramePlan {
    pub payload_len: usize,
    pub padding_len: usize,
    pub delay: Option<Duration>,
}

pub struct AdaptiveShaper {
    cfg: ShaperConfig,
    window: SlidingWindow,
    phase: Phase,
    rng: fastrand::Rng,
}

impl AdaptiveShaper {
    pub fn new(cfg: ShaperConfig, now: Instant) -> Result<Self> {
        cfg.validate()?;
        let window = SlidingWindow::new(cfg.window, now);
        Ok(AdaptiveShaper {
            cfg,
            window,
            phase: Phase::InteractiveWeb,
            rng: fastrand::Rng::with_seed(OsRng.next_u64()),
        })
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn window_bytes(&mut self, now: Instant) -> usize {
        self.window.total(now)
    }

    pub fn observe(&mut self, now: Instant, bytes: usize) {
        self.window.record(now, bytes);
        self.update_phase(now);
    }

    pub fn plan(&mut self, now: Instant, available: usize) -> FramePlan {
        self.update_phase(now);
        if available == 0 {
            return FramePlan {
                payload_len: 0,
                padding_len: 0,
                delay: None,
            };
        }
        match self.phase {
            Phase::Burst => self.plan_burst(available),
            Phase::InteractiveWeb => self.plan_web(available),
        }
    }

    pub fn cover_padding(&mut self) -> usize {
        self.rng.usize(self.cfg.min_padding..=self.cfg.max_padding)
    }

    fn update_phase(&mut self, now: Instant) {
        let total = self.window.total(now);
        match self.phase {
            Phase::InteractiveWeb => {
                if total >= self.cfg.burst_threshold_bytes {
                    self.phase = Phase::Burst;
                }
            }
            Phase::Burst => {
                let exit_below = self.cfg.burst_threshold_bytes / 100 * self.cfg.burst_exit_percent;
                if total < exit_below {
                    self.phase = Phase::InteractiveWeb;
                }
            }
        }
    }

    fn plan_burst(&mut self, available: usize) -> FramePlan {
        let mut padding_len = 0;
        if self.cfg.burst_jitter_permille > 0
            && self.rng.u32(0..1000) < self.cfg.burst_jitter_permille
        {
            padding_len = self.rng.usize(1..=self.cfg.burst_jitter_max);
        }
        let payload_len = available.min(MAX_BODY_LEN - INNER_HEADER_LEN - padding_len);
        FramePlan {
            payload_len,
            padding_len,
            delay: None,
        }
    }

    fn plan_web(&mut self, available: usize) -> FramePlan {
        let body = self.cfg.profile.sample(&mut self.rng);
        let room = body - INNER_HEADER_LEN;
        let max_payload = room - self.cfg.min_padding;
        let (payload_len, padding_len) = if available <= max_payload {
            (available, room - available)
        } else {
            let extra = self
                .rng
                .usize(0..=(self.cfg.max_padding - self.cfg.min_padding));
            (max_payload, self.cfg.min_padding + extra)
        };
        let delay = if self.cfg.web_delay_permille > 0
            && !self.cfg.web_delay_max.is_zero()
            && self.rng.u32(0..1000) < self.cfg.web_delay_permille
        {
            let nanos = self.cfg.web_delay_max.as_nanos() as u64;
            Some(Duration::from_nanos(self.rng.u64(1..=nanos)))
        } else {
            None
        };
        FramePlan {
            payload_len,
            padding_len,
            delay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shaper() -> (AdaptiveShaper, Instant) {
        let now = Instant::now();
        (
            AdaptiveShaper::new(ShaperConfig::default(), now).unwrap(),
            now,
        )
    }

    #[test]
    fn starts_in_web_phase_with_padding_in_range() {
        let (mut shaper, now) = shaper();
        assert_eq!(shaper.phase(), Phase::InteractiveWeb);
        for available in [1usize, 20, 100, 500, 1500, 10_000] {
            for _ in 0..500 {
                let plan = shaper.plan(now, available);
                assert!(plan.padding_len >= 16, "padding {}", plan.padding_len);
                assert!(plan.payload_len >= 1 && plan.payload_len <= available);
                assert!(INNER_HEADER_LEN + plan.payload_len + plan.padding_len <= MAX_BODY_LEN);
            }
        }
    }

    #[test]
    fn web_frames_vary_in_size() {
        let (mut shaper, now) = shaper();
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..300 {
            let plan = shaper.plan(now, 4000);
            sizes.insert(plan.payload_len + plan.padding_len);
        }
        assert!(sizes.len() > 60);
    }

    #[test]
    fn enters_burst_over_threshold_and_drops_padding() {
        let (mut shaper, now) = shaper();
        shaper.observe(now, 32 * 1024);
        assert_eq!(shaper.phase(), Phase::InteractiveWeb);
        shaper.observe(now + Duration::from_millis(50), 40 * 1024);
        assert_eq!(shaper.phase(), Phase::Burst);

        let later = now + Duration::from_millis(60);
        let mut zero_padding = 0;
        for _ in 0..1000 {
            let plan = shaper.plan(later, 100_000);
            assert!(plan.padding_len <= 24);
            assert_eq!(plan.delay, None);
            assert!(plan.payload_len >= 16_000);
            if plan.padding_len == 0 {
                zero_padding += 1;
            }
        }
        assert!(zero_padding > 900);
    }

    #[test]
    fn returns_to_web_when_traffic_dies_down() {
        let (mut shaper, now) = shaper();
        shaper.observe(now, 200 * 1024);
        assert_eq!(shaper.phase(), Phase::Burst);
        let quiet = now + Duration::from_millis(400);
        let plan = shaper.plan(quiet, 300);
        assert_eq!(shaper.phase(), Phase::InteractiveWeb);
        assert!(plan.padding_len >= 16);
    }

    #[test]
    fn window_slides_instead_of_resetting() {
        let (mut shaper, now) = shaper();
        shaper.observe(now, 10_000);
        shaper.observe(now + Duration::from_millis(120), 10_000);
        assert_eq!(
            shaper.window_bytes(now + Duration::from_millis(200)),
            20_000
        );
        assert_eq!(
            shaper.window_bytes(now + Duration::from_millis(300)),
            10_000
        );
        assert_eq!(shaper.window_bytes(now + Duration::from_millis(500)), 0);
    }

    #[test]
    fn web_delay_is_bounded_and_sometimes_present() {
        let (mut shaper, now) = shaper();
        let mut delayed = 0;
        for _ in 0..2000 {
            if let Some(delay) = shaper.plan(now, 200).delay {
                assert!(delay <= Duration::from_millis(6));
                delayed += 1;
            }
        }
        assert!(delayed > 100 && delayed < 600);
    }

    #[test]
    fn invalid_configs_are_refused() {
        let mut cfg = ShaperConfig::default();
        cfg.min_padding = 200;
        assert!(cfg.validate().is_err());

        let mut cfg = ShaperConfig::default();
        cfg.window = Duration::from_millis(1);
        assert!(cfg.validate().is_err());

        let mut cfg = ShaperConfig::default();
        cfg.profile = SizeProfile::new(vec![SizeBucket {
            min_body: 8,
            max_body: 30,
            weight: 1,
        }])
        .unwrap();
        assert!(cfg.validate().is_err());

        let mut cfg = ShaperConfig::default();
        cfg.profile = SizeProfile::new(vec![SizeBucket {
            min_body: 100,
            max_body: MAX_BODY_LEN,
            weight: 1,
        }])
        .unwrap();
        assert!(cfg.validate().is_err());

        assert!(SizeProfile::new(vec![]).is_err());
    }
}
