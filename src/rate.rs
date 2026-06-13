use std::{
    collections::VecDeque,
    io::{self, BufRead, Write},
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::api::ensure_success_ref;

pub(crate) const DEFAULT_RATE_WINDOW_SECONDS: u64 = 10;

pub(crate) fn watch_rate(api_url: &str, window: Duration) -> Result<()> {
    let client = Client::builder()
        .timeout(None)
        .build()
        .context("failed to build HTTP client")?;
    let stream_url = format!("{}/api/hash-results/stream", api_url.trim_end_matches('/'));
    let response = client
        .get(&stream_url)
        .send()
        .with_context(|| format!("failed to connect to {stream_url}"))?;
    ensure_success_ref(&response, "rate stream connection")?;

    let mut tracker = RateTracker::new(window);
    let reader = io::BufReader::new(response);
    for line in reader.lines() {
        let line = line.context("failed to read rate stream")?;
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let event: RateEvent = serde_json::from_str(data).context("failed to parse rate event")?;
        let Some(rate) = tracker.update(event.total_tests, event.timestamp_ms) else {
            continue;
        };
        println!(
            "total_tests={} rate_per_second={:.3}",
            event.total_tests, rate
        );
        io::stdout().flush().context("failed to flush stdout")?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RateEvent {
    total_tests: f64,
    timestamp_ms: u64,
}

struct RateTracker {
    window: Duration,
    samples: VecDeque<(u64, f64)>,
}

impl RateTracker {
    fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    fn update(&mut self, total_tests: f64, timestamp_ms: u64) -> Option<f64> {
        self.samples.push_back((timestamp_ms, total_tests));
        let window_ms = self.window.as_millis() as u64;
        while self
            .samples
            .front()
            .is_some_and(|(sample_ms, _)| timestamp_ms.saturating_sub(*sample_ms) > window_ms)
        {
            self.samples.pop_front();
        }
        let (first_ms, first_total) = *self.samples.front()?;
        let elapsed_ms = timestamp_ms.saturating_sub(first_ms);
        if elapsed_ms == 0 {
            return Some(0.0);
        }
        let added = (total_tests - first_total).max(0.0);
        Some(added / (elapsed_ms as f64 / 1000.0))
    }
}
