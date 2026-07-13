use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AcceptMetrics {
    accepted: AtomicU64,
    admitted: AtomicU64,
    shed: AtomicU64,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    in_handshake: AtomicUsize,
    peak_in_handshake: AtomicUsize,
    handshake_ok: AtomicU64,
    handshake_err: AtomicU64,
    handshake_timed_out: AtomicU64,
    served: AtomicU64,
}

impl AcceptMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_admitted(&self) {
        self.admitted.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_shed(&self) {
        self.shed.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_handshake_ok(&self) {
        self.handshake_ok.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_handshake_err(&self) {
        self.handshake_err.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_handshake_timed_out(&self) {
        self.handshake_timed_out.fetch_add(1, Ordering::SeqCst);
    }
    pub fn record_served(&self) {
        self.served.fetch_add(1, Ordering::SeqCst);
    }

    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }
    pub fn admitted(&self) -> u64 {
        self.admitted.load(Ordering::SeqCst)
    }
    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::SeqCst)
    }
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }
    pub fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }
    pub fn in_handshake(&self) -> usize {
        self.in_handshake.load(Ordering::SeqCst)
    }
    pub fn peak_in_handshake(&self) -> usize {
        self.peak_in_handshake.load(Ordering::SeqCst)
    }
    pub fn handshake_ok(&self) -> u64 {
        self.handshake_ok.load(Ordering::SeqCst)
    }
    pub fn handshake_err(&self) -> u64 {
        self.handshake_err.load(Ordering::SeqCst)
    }
    pub fn handshake_timed_out(&self) -> u64 {
        self.handshake_timed_out.load(Ordering::SeqCst)
    }
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::SeqCst)
    }

    pub fn enter_in_flight(self: &Arc<Self>) -> InFlightGuard {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(current, Ordering::SeqCst);
        InFlightGuard(self.clone())
    }

    pub fn enter_handshake(self: &Arc<Self>) -> HandshakeGuard {
        let current = self.in_handshake.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_handshake.fetch_max(current, Ordering::SeqCst);
        HandshakeGuard(self.clone())
    }
}

pub struct InFlightGuard(Arc<AcceptMetrics>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct HandshakeGuard(Arc<AcceptMetrics>);

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        self.0.in_handshake.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn in_flight_guard_tracks_peak_and_releases() {
        let metrics = AcceptMetrics::new();
        {
            let _g1 = metrics.enter_in_flight();
            assert_eq!(metrics.in_flight(), 1);
            {
                let _g2 = metrics.enter_in_flight();
                assert_eq!(metrics.in_flight(), 2);
                assert_eq!(metrics.peak_in_flight(), 2);
            }
            assert_eq!(metrics.in_flight(), 1);
            assert_eq!(metrics.peak_in_flight(), 2);
        }
        assert_eq!(metrics.in_flight(), 0);
        assert_eq!(metrics.peak_in_flight(), 2);
    }

    #[test]
    fn handshake_guard_tracks_peak_and_releases() {
        let metrics = AcceptMetrics::new();
        {
            let _g = metrics.enter_handshake();
            assert_eq!(metrics.in_handshake(), 1);
            assert_eq!(metrics.peak_in_handshake(), 1);
        }
        assert_eq!(metrics.in_handshake(), 0);
        assert_eq!(metrics.peak_in_handshake(), 1);
    }
}
