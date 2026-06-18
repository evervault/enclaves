use std::time::Duration;

use crate::server::config::AcceptorConfig;
use crate::server::metrics::AcceptMetrics;
use crate::server::test_support::{
    settle, settle_until, spawn_policy_server, FakeHandshaker, HandshakeBehaviour,
    ScriptedListener, ScriptedListenerBuilder,
};

fn config(connections: usize, handshakes: usize, timeout: Option<Duration>) -> AcceptorConfig {
    AcceptorConfig {
        max_concurrent_connections: connections,
        max_concurrent_handshakes: handshakes,
        handshake_timeout: timeout,
    }
}

// ===========================================================================
// §4.2 Handshake concurrency
// ===========================================================================

// Test 8 (serial arm) — under serial config a slow handshake blocks every other
// connection: nothing completes while conn 0 is mid-handshake, and conn 0
// completes *first* once it finishes.
#[tokio::test(start_paused = true)]
async fn test8_slow_handshake_blocks_others_serial() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    let slow = builder.push(HandshakeBehaviour::SucceedAfter(Duration::from_secs(10)));
    builder.push_many(9, HandshakeBehaviour::Instant);

    let handle = spawn_policy_server(
        builder.build(),
        handshaker.clone(),
        AcceptorConfig::serial_compat(),
        metrics.clone(),
    );

    // Loop is blocked inline on conn 0's 10s handshake; clock has not advanced.
    settle().await;
    assert_eq!(
        handshaker.completion_order(),
        Vec::<usize>::new(),
        "serial: instant conns must be stuck behind the slow handshake"
    );
    assert_eq!(
        metrics.accepted(),
        1,
        "serial: only conn 0 pulled off the listener"
    );

    // Let conn 0 finish; the rest then drain in order.
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(settle_until(|| handshaker.completion_order().len() == 10).await);
    let order = handshaker.completion_order();
    assert_eq!(order[0], slow, "serial: the slow conn completes first");

    handle.abort();
}

// Test 8 (concurrent arm) — the 9 instant conns complete while conn 0 is still
// handshaking; conn 0 completes last (only after we advance past its deadline).
#[tokio::test(start_paused = true)]
async fn test8_slow_handshake_does_not_block_others_concurrent() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    let slow = builder.push(HandshakeBehaviour::SucceedAfter(Duration::from_secs(10)));
    builder.push_many(9, HandshakeBehaviour::Instant);

    let handle = spawn_policy_server(
        builder.build(),
        handshaker.clone(),
        AcceptorConfig::concurrent_default(),
        metrics.clone(),
    );

    assert!(
        settle_until(|| handshaker.completion_order().len() == 9).await,
        "concurrent: instant conns complete while conn 0 handshakes"
    );
    assert!(
        !handshaker.completion_order().contains(&slow),
        "concurrent: slow conn must not have completed yet"
    );

    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(settle_until(|| handshaker.completion_order().contains(&slow)).await);

    handle.abort();
}

// Test 9 (serial arm) — a stalled handshake on conn 0 wedges the accept loop:
// the listener stays at depth 1, no further connections are pulled.
#[tokio::test(start_paused = true)]
async fn test9_stalled_handshake_blocks_accept_serial() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push(HandshakeBehaviour::Stall);
    builder.push_many(5, HandshakeBehaviour::Instant);

    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        AcceptorConfig::serial_compat(),
        metrics.clone(),
    );

    settle().await;
    assert_eq!(
        metrics.accepted(),
        1,
        "serial: loop stuck on conn 0's stalled handshake"
    );

    // Even after a long time the stall never resolves, so the loop never advances.
    tokio::time::advance(Duration::from_secs(600)).await;
    settle().await;
    assert_eq!(
        metrics.accepted(),
        1,
        "serial: still only conn 0 was accepted"
    );

    handle.abort();
}

// Test 9 (concurrent arm) — a stalled handshake does not stop the accept loop:
// all connections are pulled off the listener and the instant ones complete.
#[tokio::test(start_paused = true)]
async fn test9_stalled_handshake_keeps_accepting_concurrent() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push(HandshakeBehaviour::Stall);
    builder.push_many(5, HandshakeBehaviour::Instant);

    let handle = spawn_policy_server(
        builder.build(),
        handshaker.clone(),
        AcceptorConfig::concurrent_default(),
        metrics.clone(),
    );

    assert!(
        settle_until(|| metrics.accepted() == 6).await,
        "concurrent: accept loop keeps draining past the stalled handshake"
    );
    assert!(
        settle_until(|| handshaker.completion_order().len() == 5).await,
        "concurrent: the 5 instant conns get through the handshake phase"
    );

    handle.abort();
}

// Test 10 — peak concurrent handshakes is bounded by `max_concurrent_handshakes`.
// Inject 100 slow handshakes against a small handshake cap; the cap binds and is
// never exceeded (excess is shed).
#[tokio::test(start_paused = true)]
async fn test10_peak_handshakes_bounded() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many(
        100,
        HandshakeBehaviour::SucceedAfter(Duration::from_secs(10)),
    );

    let cfg = config(1000, 8, None);
    let handle = spawn_policy_server(builder.build(), handshaker, cfg, metrics.clone());

    // All 100 are pulled off the listener; only 8 can be in handshake at once.
    assert!(settle_until(|| metrics.accepted() == 100).await);
    assert!(
        metrics.peak_in_handshake() <= 8,
        "peak in-handshake {} exceeded the cap of 8",
        metrics.peak_in_handshake()
    );
    assert_eq!(
        metrics.peak_in_handshake(),
        8,
        "the handshake cap should bind"
    );

    handle.abort();
}

// ===========================================================================
// §4.3 Handshake timeout
// ===========================================================================

// Test 11 — a stalled handshake is abandoned after `handshake_timeout`, its slot
// is released, and a connection injected afterwards can proceed.
#[tokio::test(start_paused = true)]
async fn test11_stalled_handshake_times_out_and_releases_slot() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let (listener, sender) = ScriptedListener::channel();

    // Single handshake slot so a later conn can only proceed once it's freed.
    let cfg = config(10, 1, Some(Duration::from_secs(5)));
    let handle = spawn_policy_server(listener, handshaker.clone(), cfg, metrics.clone());

    sender.send(HandshakeBehaviour::Stall);
    assert!(settle_until(|| metrics.in_handshake() == 1).await);
    assert_eq!(metrics.handshake_timed_out(), 0);

    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(settle_until(|| metrics.handshake_timed_out() == 1).await);
    assert_eq!(
        metrics.in_handshake(),
        0,
        "handshake slot released after timeout"
    );

    // A fresh connection can now grab the freed slot and complete.
    let fresh = sender.send(HandshakeBehaviour::Instant);
    assert!(settle_until(|| handshaker.completion_order().contains(&fresh)).await);

    handle.abort();
}

// Test 12 — a handshake completing just under the deadline succeeds; one that
// would exceed it is timed out. Pins the boundary.
#[tokio::test(start_paused = true)]
async fn test12_handshake_timeout_boundary() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let (listener, sender) = ScriptedListener::channel();

    let cfg = config(10, 10, Some(Duration::from_secs(10)));
    let handle = spawn_policy_server(listener, handshaker.clone(), cfg, metrics.clone());

    // Just under: 9s handshake with a 10s budget succeeds. Let the task arm its
    // timers (under paused time, `advance` only fires already-registered timers).
    let under = sender.send(HandshakeBehaviour::SucceedAfter(Duration::from_secs(9)));
    assert!(settle_until(|| metrics.in_handshake() == 1).await);
    tokio::time::advance(Duration::from_secs(9)).await;
    assert!(settle_until(|| handshaker.completion_order().contains(&under)).await);
    assert_eq!(metrics.handshake_timed_out(), 0);

    // Over: a 20s handshake (started ~now) hits the 10s budget first.
    let over = sender.send(HandshakeBehaviour::SucceedAfter(Duration::from_secs(20)));
    assert!(settle_until(|| metrics.in_handshake() == 1).await);
    tokio::time::advance(Duration::from_secs(11)).await;
    assert!(settle_until(|| metrics.handshake_timed_out() == 1).await);
    assert!(
        !handshaker.completion_order().contains(&over),
        "over-deadline conn must not complete"
    );

    handle.abort();
}

// Test 13 — with the timeout disabled (`None`, the serial default) a stalled
// handshake is *never* abandoned. Documents today's behaviour and proves `None`
// is wired through.
#[tokio::test(start_paused = true)]
async fn test13_no_timeout_stall_not_abandoned() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let (listener, sender) = ScriptedListener::channel();

    let handle = spawn_policy_server(
        listener,
        handshaker,
        AcceptorConfig::serial_compat(),
        metrics.clone(),
    );

    sender.send(HandshakeBehaviour::Stall);
    assert!(settle_until(|| metrics.in_handshake() == 1).await);

    // No timeout configured: advancing the clock far does not abandon it.
    tokio::time::advance(Duration::from_secs(3600)).await;
    settle().await;
    assert_eq!(
        metrics.handshake_timed_out(),
        0,
        "no timeout => never abandoned"
    );
    assert_eq!(
        metrics.in_handshake(),
        1,
        "still stuck in the handshake phase"
    );

    handle.abort();
}

// ===========================================================================
// §4.4 Backpressure & resource-exhaustion protection
// ===========================================================================

// Test 15 — total in-flight connections are capped at `max_concurrent_connections`.
// Fire 4×cap connections; peak in-flight never exceeds the cap (excess is shed).
#[tokio::test(start_paused = true)]
async fn test15_total_in_flight_capped() {
    let cap = 10usize;
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many(
        4 * cap,
        HandshakeBehaviour::SucceedAfter(Duration::from_secs(5)),
    );

    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        config(cap, cap, None),
        metrics.clone(),
    );

    // While the admitted connections sit in their handshake, in-flight is pinned
    // at the cap and the rest are shed.
    assert!(settle_until(|| metrics.in_flight() == cap).await);
    assert!(
        metrics.peak_in_flight() <= cap,
        "peak in-flight {} exceeded cap {cap}",
        metrics.peak_in_flight()
    );
    assert_eq!(
        metrics.peak_in_flight(),
        cap,
        "the connection cap should bind"
    );

    handle.abort();
}

// Test 16 — in-handshake concurrency is capped by `max_concurrent_handshakes`
// *independently* of the total-connection cap. Connections injected paced enough
// to clear an instant handshake then linger in a long serve accumulate in-flight
// well beyond the (much smaller) handshake cap.
#[tokio::test(start_paused = true)]
async fn test16_handshake_cap_independent_of_connection_cap() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let (listener, sender) = ScriptedListener::channel();

    // conn cap 20, handshake cap 2.
    let handle = spawn_policy_server(listener, handshaker, config(20, 2, None), metrics.clone());

    for _ in 0..10 {
        sender.send_spec(
            HandshakeBehaviour::Instant,
            None,
            Some(Duration::from_secs(100)),
        );
        settle().await;
    }

    assert!(
        settle_until(|| metrics.in_flight() == 10).await,
        "all 10 connections should be in-flight (serving)"
    );
    assert!(
        metrics.in_flight() > 2,
        "total in-flight is allowed to exceed the handshake cap"
    );
    assert!(
        metrics.peak_in_handshake() <= 2,
        "handshakes remain bounded by their own cap, independent of the conn cap"
    );

    handle.abort();
}

// Test 17 — connection overflow is rejected immediately (no queue): the accept
// loop keeps draining (never stalls), excess connections are shed, and the
// accounting balances.
#[tokio::test(start_paused = true)]
async fn test17_connection_overflow_is_shed() {
    let cap = 4usize;
    let offered = 20usize;
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    // Long serve so admitted conns hold their connection permit; instant handshake.
    builder.push_many_spec(
        offered,
        HandshakeBehaviour::Instant,
        Some(Duration::from_secs(100)),
    );

    // Large handshake cap so the *connection* cap is the binding constraint.
    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        config(cap, 1000, None),
        metrics.clone(),
    );

    assert!(
        settle_until(|| metrics.accepted() as usize == offered).await,
        "accept loop drains every connection without stalling on admission"
    );
    assert!(settle_until(|| metrics.in_flight() == cap).await);
    assert!(metrics.shed() > 0, "overflow must be shed");
    assert_eq!(
        metrics.served() + metrics.shed() + metrics.in_flight() as u64,
        offered as u64,
        "served + shed + in-flight == offered"
    );

    handle.abort();
}

// Test 18 — handshake-slot overflow waits for another connection to become free and doesn't shed
#[tokio::test(start_paused = true)]
async fn test18_handshake_slot_overflow_awaits_tasks() {
    let offered = 20usize;
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many(
        offered,
        HandshakeBehaviour::SucceedAfter(Duration::from_secs(100)),
    );

    // Plenty of connection slots, only 2 handshake slots.
    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        config(1000, 2, None),
        metrics.clone(),
    );

    assert!(settle_until(|| metrics.accepted() as usize == offered).await);
    assert!(settle_until(|| metrics.in_handshake() == 2).await);
    assert!(
        metrics.shed() == 0,
        "avoid shedding on handshake-slot exhaustion"
    );
    assert!(metrics.peak_in_flight() == offered);
    assert!(metrics.peak_in_handshake() <= 2);

    handle.abort();
}

// Test 19 — latency stays flat under overload: with no queue, the time for an
// admitted connection to complete does not grow with offered load.
#[tokio::test(start_paused = true)]
async fn test19_latency_flat_under_overload() {
    let handshake_d = Duration::from_secs(2);
    let small = first_completion_latency(8, handshake_d).await;
    let large = first_completion_latency(10_000, handshake_d).await;
    assert_eq!(
        small, large,
        "admitted-connection latency must be independent of offered load (no queue)"
    );
}

/// Virtual time from server start until the first connection completes its
/// handshake, for a burst of `offered` connections (conn/handshake cap 8).
async fn first_completion_latency(offered: usize, handshake_d: Duration) -> Duration {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many(offered, HandshakeBehaviour::SucceedAfter(handshake_d));

    let handle = spawn_policy_server(
        builder.build(),
        handshaker.clone(),
        config(8, 8, None),
        metrics,
    );
    let start = tokio::time::Instant::now();
    settle().await;
    tokio::time::advance(handshake_d + Duration::from_millis(1)).await;
    assert!(settle_until(|| !handshaker.completion_order().is_empty()).await);
    let elapsed = start.elapsed();
    handle.abort();
    elapsed
}

// Test 20 — a large instantaneous burst does not spawn unbounded tasks: live
// in-flight stays bounded by the connection cap and the rest are shed.
#[tokio::test(start_paused = true)]
async fn test20_burst_does_not_spawn_unbounded_tasks() {
    let cap = 16usize;
    let offered = 10_000usize;
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many_spec(
        offered,
        HandshakeBehaviour::Instant,
        Some(Duration::from_secs(100)),
    );

    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        config(cap, cap, None),
        metrics.clone(),
    );

    assert!(settle_until(|| metrics.accepted() as usize == offered).await);
    assert!(
        metrics.peak_in_flight() <= cap,
        "live in-flight {} exceeded cap {cap} under burst",
        metrics.peak_in_flight()
    );
    assert_eq!(
        metrics.shed() as usize,
        offered - cap,
        "everything over the cap is shed"
    );

    handle.abort();
}

// Test 21 — both permits are released on every exit path (handshake success →
// serve end, handshake error, handshake timeout); steady-state gauges return to
// zero and a fresh connection is still admitted afterwards.
#[tokio::test(start_paused = true)]
async fn test21_permits_released_on_every_exit_path() {
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let (listener, sender) = ScriptedListener::channel();
    let handle = spawn_policy_server(
        listener,
        handshaker.clone(),
        config(4, 4, Some(Duration::from_secs(5))),
        metrics.clone(),
    );

    let idle = || metrics.in_flight() == 0 && metrics.in_handshake() == 0;

    // (1) handshake success → serve runs to completion (EOF) → both released.
    // This path also covers a "serve error": the serve task ending releases the
    // connection permit identically.
    sender.send(HandshakeBehaviour::Instant);
    assert!(settle_until(|| metrics.served() == 1).await);
    assert!(settle_until(idle).await, "released after success");

    // (2) handshake error → both released without ever serving.
    sender.send(HandshakeBehaviour::Fail);
    assert!(settle_until(|| metrics.handshake_err() == 1).await);
    assert!(settle_until(idle).await, "released after handshake error");

    // (3) handshake timeout → both released when the deadline fires.
    sender.send(HandshakeBehaviour::Stall);
    assert!(settle_until(|| metrics.in_handshake() == 1).await);
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(settle_until(|| metrics.handshake_timed_out() == 1).await);
    assert!(settle_until(idle).await, "released after handshake timeout");

    // Capacity is fully restored: a fresh connection is still admitted + served.
    let fresh = sender.send(HandshakeBehaviour::Instant);
    assert!(settle_until(|| handshaker.completion_order().contains(&fresh)).await);

    handle.abort();
}

// ===========================================================================
// §4.5 Throughput / soak
// ===========================================================================

// Test 23 — under slow handshakes the concurrent profile drains a wave of K
// handshakes in a single `d`, whereas the serial profile completes only one per
// `d`. Uses the virtual clock so the comparison is deterministic.
#[tokio::test(start_paused = true)]
async fn test23_concurrent_faster_than_serial_under_slow_handshakes() {
    let d = Duration::from_secs(10);
    let k = 8usize;

    // Concurrent: all K complete in one handshake wave.
    {
        let metrics = AcceptMetrics::new();
        let handshaker = FakeHandshaker::new();
        let mut builder = ScriptedListenerBuilder::new();
        builder.push_many(k, HandshakeBehaviour::SucceedAfter(d));
        let handle = spawn_policy_server(
            builder.build(),
            handshaker.clone(),
            config(64, 64, None),
            metrics,
        );
        settle().await;
        tokio::time::advance(d + Duration::from_secs(1)).await;
        assert!(
            settle_until(|| handshaker.completion_order().len() == k).await,
            "concurrent: all {k} complete in a single handshake wave"
        );
        handle.abort();
    }

    // Serial: only one completes per wave of `d`.
    {
        let metrics = AcceptMetrics::new();
        let handshaker = FakeHandshaker::new();
        let mut builder = ScriptedListenerBuilder::new();
        builder.push_many(k, HandshakeBehaviour::SucceedAfter(d));
        let handle = spawn_policy_server(
            builder.build(),
            handshaker.clone(),
            AcceptorConfig::serial_compat(),
            metrics,
        );
        settle().await;
        tokio::time::advance(d + Duration::from_secs(1)).await;
        assert!(settle_until(|| !handshaker.completion_order().is_empty()).await);
        assert_eq!(
            handshaker.completion_order().len(),
            1,
            "serial: only one completion per handshake wave"
        );
        handle.abort();
    }
}

// ===========================================================================
// §4.6 Thread-safety (multi-thread runtime)
// ===========================================================================

// Test 24 — under a multi-thread runtime (real parallelism, real time) the two
// semaphores still hold their caps exactly and the shed/served accounting is
// exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test24_concurrent_admission_under_parallelism() {
    let offered = 200usize;
    let metrics = AcceptMetrics::new();
    let handshaker = FakeHandshaker::new();
    let mut builder = ScriptedListenerBuilder::new();
    builder.push_many(
        offered,
        HandshakeBehaviour::SucceedAfter(Duration::from_millis(5)),
    );

    let handle = spawn_policy_server(
        builder.build(),
        handshaker,
        config(32, 8, None),
        metrics.clone(),
    );

    assert!(
        crate::server::test_support::wait_until(
            || (metrics.served() + metrics.shed()) as usize == offered,
            Duration::from_secs(10),
        )
        .await,
        "all offered connections accounted for"
    );

    assert!(
        metrics.peak_in_handshake() <= 8,
        "handshake cap held under real parallelism"
    );
    assert!(
        metrics.peak_in_flight() <= 32,
        "connection cap held under real parallelism"
    );
    assert_eq!(metrics.accepted() as usize, offered);
    assert_eq!(
        (metrics.served() + metrics.shed()) as usize,
        offered,
        "exact served/shed accounting"
    );

    handle.abort();
}
