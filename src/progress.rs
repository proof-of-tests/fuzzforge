use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Context, Result};

pub(crate) struct ProgressDisplay {
    proven_before: f64,
    update_in_place: bool,
    proven_added: Arc<AtomicF64>,
    running: Arc<AtomicBool>,
    spinner: Option<JoinHandle<()>>,
    spinner_done: Option<Receiver<()>>,
    finished: bool,
}

impl ProgressDisplay {
    pub(crate) fn start(proven_before: f64, update_in_place: bool) -> Self {
        eprintln!("proven_before={proven_before:.3}");
        let proven_added = Arc::new(AtomicF64::new(0.0));
        let running = Arc::new(AtomicBool::new(update_in_place));
        let (done_tx, done_rx) = mpsc::channel();
        let spinner = if update_in_place {
            Some(spawn_spinner(
                Arc::clone(&proven_added),
                Arc::clone(&running),
                done_tx,
            ))
        } else {
            None
        };
        Self {
            proven_before,
            update_in_place,
            proven_added,
            running,
            spinner,
            spinner_done: Some(done_rx),
            finished: false,
        }
    }

    pub(crate) fn update(&self, estimated_observations: f64) -> Result<()> {
        let proven_added = (estimated_observations - self.proven_before).max(0.0);
        self.proven_added.store(proven_added, Ordering::Relaxed);
        if self.update_in_place {
            Ok(())
        } else {
            self.write_progress(proven_added, true)
        }
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.stop_spinner();
        if self.update_in_place {
            let proven_added = self.proven_added.load(Ordering::Relaxed);
            self.write_progress(proven_added, true)?;
        }
        self.finished = true;
        Ok(())
    }

    fn stop_spinner(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(done) = self.spinner_done.take() {
            let _ = done.recv_timeout(Duration::from_millis(50));
        }
        if self
            .spinner
            .as_ref()
            .is_some_and(|spinner| spinner.is_finished())
            && let Some(spinner) = self.spinner.take()
        {
            let _ = spinner.join();
        }
    }

    fn write_progress(&self, proven_added: f64, newline: bool) -> Result<()> {
        let mut stderr = io::stderr().lock();
        if self.update_in_place {
            write!(stderr, "\rproven_added={proven_added:.3}  ")?;
        } else {
            write!(stderr, "proven_added={proven_added:.3}")?;
        }
        if newline {
            writeln!(stderr)?;
        }
        stderr.flush().context("failed to flush progress output")
    }
}

impl Drop for ProgressDisplay {
    fn drop(&mut self) {
        self.stop_spinner();
        if !self.update_in_place || self.finished {
            return;
        }
        let _ = writeln!(io::stderr().lock());
    }
}

fn spawn_spinner(
    proven_added: Arc<AtomicF64>,
    running: Arc<AtomicBool>,
    done: mpsc::Sender<()>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        const FRAME_INTERVAL: Duration = Duration::from_millis(250);
        const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
        let mut frame_index = 0;
        while running.load(Ordering::Relaxed) {
            let proven_added = proven_added.load(Ordering::Relaxed);
            let mut stderr = io::stderr().lock();
            let _ = write!(
                stderr,
                "\rproven_added={proven_added:.3} {}",
                FRAMES[frame_index]
            );
            let _ = stderr.flush();
            frame_index = (frame_index + 1) % FRAMES.len();
            thread::sleep(FRAME_INTERVAL);
        }
        let _ = done.send(());
    })
}

#[derive(Debug)]
struct AtomicF64 {
    bits: AtomicU64,
}

impl AtomicF64 {
    fn new(value: f64) -> Self {
        Self {
            bits: AtomicU64::new(value.to_bits()),
        }
    }

    fn load(&self, order: Ordering) -> f64 {
        f64::from_bits(self.bits.load(order))
    }

    fn store(&self, value: f64, order: Ordering) {
        self.bits.store(value.to_bits(), order);
    }
}
