using System.Diagnostics;
using XMesh.Runtime;
using Xunit;

namespace XMesh.Tests;

/// <summary>Deterministic: the queue's clock is fake, so hedging thresholds are exact and nothing sleeps.</summary>
public class ChunkWorkQueueTests
{
    private sealed class Clock
    {
        public long Ticks;
        public long Now() => Ticks;
        public void Advance(double seconds) => Ticks += (long)(seconds * Stopwatch.Frequency);
    }

    private static (ChunkWorkQueue, Clock) Make(int chunks, bool hedging = true, double hedgeAfter = 1.0)
    {
        var c = new Clock();
        return (new ChunkWorkQueue(Enumerable.Range(0, chunks), hedging, TimeSpan.FromSeconds(hedgeAfter), c.Now), c);
    }

    private static async Task<ChunkWorkQueue.Lease> Take(ChunkWorkQueue q, int worker)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var (ok, lease) = await q.NextAsync(worker, cts.Token);
        Assert.True(ok);
        return lease;
    }

    [Fact]
    public async Task Hands_out_every_chunk_once_in_order_and_finishes()
    {
        var (q, _) = Make(4);
        var got = new List<int>();
        for (int i = 0; i < 4; i++) { var l = await Take(q, 0); Assert.False(l.IsHedge); got.Add(l.Index); Assert.True(q.Complete(l.Index)); }
        Assert.Equal(new[] { 0, 1, 2, 3 }, got);
        Assert.True(q.IsFinished);
        var (ok, _) = await q.NextAsync(0, CancellationToken.None);
        Assert.False(ok);                                            // workers are told to exit
    }

    [Fact]
    public async Task No_hedge_before_the_threshold()
    {
        var (q, clock) = Make(1, hedgeAfter: 1.0);
        var slow = await Take(q, 0);                                 // worker 0 takes the only chunk and stalls
        clock.Advance(0.5);
        using var cts = new CancellationTokenSource(150);            // idle worker 1 asks; nothing is due yet
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.NextAsync(1, cts.Token));
        Assert.Equal(0, q.HedgesStarted);
    }

    [Fact]
    public async Task Idle_worker_hedges_the_oldest_stalled_chunk_after_the_threshold()
    {
        var (q, clock) = Make(1, hedgeAfter: 1.0);
        var slow = await Take(q, 0);
        clock.Advance(1.5);
        var hedge = await Take(q, 1);
        Assert.True(hedge.IsHedge);
        Assert.Equal(slow.Index, hedge.Index);
        Assert.Equal(1, q.HedgesStarted);
    }

    [Fact]
    public async Task First_completion_wins_second_is_reported_as_loser()
    {
        var (q, clock) = Make(1);
        var a = await Take(q, 0); clock.Advance(2); var b = await Take(q, 1);
        Assert.True(q.Complete(b.Index));      // hedge wins
        Assert.False(q.Complete(a.Index));     // original arrives later: must NOT count twice
        Assert.Equal(0, q.Remaining);
    }

    [Fact]
    public async Task A_worker_never_hedges_a_chunk_it_already_holds()
    {
        var (q, clock) = Make(1);
        await Take(q, 0);
        clock.Advance(5);
        using var cts = new CancellationTokenSource(150);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.NextAsync(0, cts.Token));   // same worker: nothing to do
    }

    [Fact]
    public async Task At_most_one_hedge_per_chunk_so_load_is_bounded_at_two_fetchers()
    {
        var (q, clock) = Make(1);
        await Take(q, 0); clock.Advance(2);
        var h = await Take(q, 1); Assert.True(h.IsHedge);
        using var cts = new CancellationTokenSource(150);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.NextAsync(2, cts.Token)); // third worker gets no second hedge
        Assert.Equal(1, q.HedgesStarted);
    }

    [Fact]
    public async Task Hedging_can_be_disabled()
    {
        var (q, clock) = Make(1, hedging: false);
        await Take(q, 0); clock.Advance(100);
        using var cts = new CancellationTokenSource(150);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.NextAsync(1, cts.Token));
        Assert.Equal(0, q.HedgesStarted);
    }

    [Fact]
    public async Task Fresh_pending_chunks_take_priority_over_hedging()
    {
        var (q, clock) = Make(3);
        await Take(q, 0);                       // chunk 0 in flight
        clock.Advance(10);                      // ...and very stale
        var next = await Take(q, 1);            // but chunks 1,2 are still pending: give real work first
        Assert.False(next.IsHedge);
        Assert.Equal(1, next.Index);
    }

    [Fact]
    public async Task Failed_original_returns_the_chunk_to_pending()
    {
        var (q, _) = Make(1);
        var a = await Take(q, 0);
        q.Failed(a.Index, wasHedge: false);
        var again = await Take(q, 1);
        Assert.False(again.IsHedge);
        Assert.Equal(a.Index, again.Index);
    }

    [Fact]
    public async Task Failed_hedge_keeps_the_original_running_and_allows_a_new_hedge_later()
    {
        var (q, clock) = Make(1);
        await Take(q, 0); clock.Advance(2);
        var h = await Take(q, 1); q.Failed(h.Index, wasHedge: true);
        Assert.False(q.IsFinished);
        var h2 = await Take(q, 2);              // hedge slot was released: another worker may try
        Assert.True(h2.IsHedge);
    }

    [Fact]
    public async Task Original_gives_up_while_a_hedge_runs_the_hedge_stays_the_sole_fetcher_and_is_not_lost()
    {
        var (q, clock) = Make(1);
        var orig = await Take(q, 0); clock.Advance(2);
        var hedge = await Take(q, 1);
        q.Failed(orig.Index, wasHedge: false);          // original dies; hedge (worker 1) is now the only fetcher
        Assert.False(q.IsFinished);
        Assert.True(q.Complete(hedge.Index));           // and it can still finish the chunk
        Assert.True(q.IsFinished);
    }

    [Fact]
    public async Task Requeue_hands_the_chunk_to_another_worker_immediately()
    {
        var (q, _) = Make(2);
        var a = await Take(q, 0);                       // chunk 0
        q.Requeue(a.Index);                             // worker 0's peer does not have it
        var b = await Take(q, 1);                       // chunk 1 (still pending, FIFO)
        var c = await Take(q, 1);
        Assert.Equal(new[] { 1, 0 }, new[] { b.Index, c.Index });
    }

    [Fact]
    public async Task Requeue_and_Failed_after_completion_are_harmless()
    {
        var (q, _) = Make(1);
        var a = await Take(q, 0);
        q.Complete(a.Index);
        q.Requeue(a.Index); q.Failed(a.Index, false); q.Failed(a.Index, true);
        Assert.True(q.IsFinished);
        Assert.Equal(0, q.Remaining);
    }

    [Fact]
    public async Task Waiting_worker_wakes_when_a_chunk_is_requeued()
    {
        var (q, _) = Make(1);
        var a = await Take(q, 0);
        var waiter = Task.Run(async () => (await q.NextAsync(1, CancellationToken.None)).Lease);
        await Task.Delay(100);
        Assert.False(waiter.IsCompleted);               // nothing to do yet
        q.Requeue(a.Index);
        var got = await waiter.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(a.Index, got.Index);
    }

    [Fact]
    public async Task Stress_many_workers_every_chunk_completes_exactly_once_with_random_failures()
    {
        const int Chunks = 300, Workers = 12;
        var (q, _) = Make(Chunks, hedgeAfter: 0.0);     // hedge immediately: maximum contention
        var completedBy = new int[Chunks];
        var rng = new Random(1234);
        var rngLock = new object();
        bool Roll(int pct) { lock (rngLock) return rng.Next(100) < pct; }

        var tasks = Enumerable.Range(0, Workers).Select(w => Task.Run(async () =>
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while (true)
            {
                var (ok, lease) = await q.NextAsync(w, cts.Token);
                if (!ok) return;
                await Task.Yield();
                if (Roll(15)) { q.Failed(lease.Index, lease.IsHedge); continue; }        // random failure
                if (Roll(5)) { q.Requeue(lease.Index); continue; }                       // "peer lacks it"
                if (q.Complete(lease.Index)) Interlocked.Increment(ref completedBy[lease.Index]);
            }
        })).ToArray();
        await Task.WhenAll(tasks);

        Assert.True(q.IsFinished);
        for (int i = 0; i < Chunks; i++) Assert.Equal(1, completedBy[i]);               // exactly once each: no loss, no duplicates
    }
}

public class ChunkWorkQueueEdgeTests
{
    private static (ChunkWorkQueue, Action<double>) Make(int chunks)
    {
        long ticks = 0;
        var q = new ChunkWorkQueue(Enumerable.Range(0, chunks), true, TimeSpan.FromSeconds(1), () => ticks);
        return (q, s => ticks += (long)(s * Stopwatch.Frequency));
    }

    [Fact]
    public async Task Requeue_of_a_chunk_that_a_hedge_is_still_fetching_does_not_start_a_third_fetch()
    {
        var (q, advance) = Make(1);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var orig = (await q.NextAsync(0, cts.Token)).Lease;            // worker 0 holds chunk 0
        advance(2);
        var hedge = (await q.NextAsync(1, cts.Token)).Lease;           // worker 1 hedges it
        Assert.True(hedge.IsHedge);

        q.Requeue(orig.Index);                                          // worker 0's peer "does not have it"

        // Worker 1 is still fetching it. A brand-new worker must NOT be handed an extra copy immediately.
        using var brief = new CancellationTokenSource(200);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => q.NextAsync(2, brief.Token));

        Assert.True(q.Complete(hedge.Index));                           // and worker 1 can still finish it
        Assert.True(q.IsFinished);
    }
}

/// <summary>
/// Regression for a real hang: a worker whose peer LACKS a chunk requeues it, immediately receives the same chunk
/// again, requeues again ... forever. A worker must be able to "decline" a chunk without being re-offered it.
/// </summary>
public class ChunkWorkQueueDeclineTests
{
    [Fact]
    public async Task A_worker_that_declined_the_only_chunk_is_told_to_stop_immediately()
    {
        // With only one chunk and one worker, once that worker declines it there is truly nothing left this
        // worker could ever be given: NextAsync must return "no more work" right away, not make it wait.
        // (An earlier version of this test wrongly expected a wait/timeout here - that was itself a bug:
        // it is exactly the shape of the infinite-spin this queue exists to prevent.)
        var q = new ChunkWorkQueue(new[] { 0 }, hedging: false, TimeSpan.FromSeconds(1));
        var first = (await q.NextAsync(worker: 0, CancellationToken.None)).Lease;
        Assert.Equal(0, first.Index);

        q.Decline(first.Index, worker: 0);                     // worker 0's peer does not have chunk 0

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var (ok, _) = await q.NextAsync(0, cts.Token);
        Assert.False(ok);                                       // told to stop, not left hanging

        // A DIFFERENT worker (whose peer may have it) still gets it, and can complete it.
        var other = (await q.NextAsync(worker: 1, CancellationToken.None)).Lease;
        Assert.Equal(0, other.Index);
        Assert.True(q.Complete(0));
    }

    [Fact]
    public async Task A_worker_with_other_pending_work_still_waits_rather_than_stopping_early()
    {
        // Contrast case: TWO chunks, worker declines one but the other is still there for it to take.
        // NextAsync must hand out the second chunk, not report "no more work".
        var q = new ChunkWorkQueue(new[] { 0, 1 }, hedging: false, TimeSpan.FromSeconds(1));
        var a = (await q.NextAsync(0, CancellationToken.None)).Lease;
        Assert.Equal(0, a.Index);
        q.Decline(0, worker: 0);

        var b = (await q.NextAsync(0, CancellationToken.None)).Lease;   // chunk 1 is still available to worker 0
        Assert.Equal(1, b.Index);
        Assert.True(q.Complete(1));
    }

    [Fact]
    public async Task When_every_LIVE_worker_has_declined_a_chunk_the_queue_reports_it_unservable()
    {
        var q = new ChunkWorkQueue(new[] { 0, 1 }, hedging: false, TimeSpan.FromSeconds(1));
        var a = (await q.NextAsync(0, CancellationToken.None)).Lease;   // chunk 0
        var b = (await q.NextAsync(1, CancellationToken.None)).Lease;   // chunk 1
        q.Complete(b.Index);
        q.Decline(a.Index, worker: 0);
        q.Decline(a.Index, worker: 1);                                   // the only other worker also lacks it

        var live = new HashSet<int> { 0, 1 };
        Assert.True(q.IsStuck(live));
        Assert.Equal(new[] { 0 }, q.Unservable(live).ToArray());
    }

    [Fact]
    public void An_EXITED_workers_declines_do_not_count_against_the_survivors()
    {
        // THE ACTUAL PRODUCTION BUG: worker 0 (fast peer) declines chunks 0-4 then exits (it only had chunk 5).
        // Worker 1 (slow peer) is still alive and has never even been asked - it must NOT be told "stuck".
        var q = new ChunkWorkQueue(Enumerable.Range(0, 6), hedging: false, TimeSpan.FromSeconds(1));
        for (int i = 0; i < 5; i++) q.Decline(i, worker: 0);            // worker 0 declines 0..4, keeps 5 (not shown)

        var onlySurvivor = new HashSet<int> { 1 };                      // worker 0 has exited: NOT in the live set
        Assert.False(q.IsStuck(onlySurvivor));
        Assert.Empty(q.Unservable(onlySurvivor));                       // nothing is unservable to worker 1 - it hasn't tried
    }

    [Fact]
    public async Task Regression_single_worker_lacking_one_chunk_still_finishes_the_rest_then_stops()
    {
        // The exact production scenario: 6 chunks, the only peer lacks chunk 2. The worker must complete 0,1,3,4,5
        // and then EXIT, so the runtime can fall through to the origin for chunk 2.
        var q = new ChunkWorkQueue(Enumerable.Range(0, 6), hedging: false, TimeSpan.FromSeconds(1));
        var live = new HashSet<int> { 0 };
        var done = new List<int>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (true)
        {
            if (q.IsStuck(live)) break;                                  // nothing this sole worker can still do
            var (ok, lease) = await q.NextAsync(0, cts.Token);
            if (!ok) break;
            if (lease.Index == 2) { q.Decline(2, worker: 0); continue; }
            q.Complete(lease.Index); done.Add(lease.Index);
        }
        Assert.Equal(new[] { 0, 1, 3, 4, 5 }, done);
        Assert.False(q.IsFinished);                                     // chunk 2 is left for the origin
        Assert.Equal(new[] { 2 }, q.Unservable(live).ToArray());
    }

    [Fact]
    public async Task Two_workers_one_lacking_different_chunks_both_finish_what_they_can()
    {
        // Regression for the two-peer production scenario: worker 0 lacks {0,2,4}, worker 1 lacks {1,3}.
        // Together they cover everything, so nobody should ever see "stuck" and all 5 chunks complete.
        var q = new ChunkWorkQueue(Enumerable.Range(0, 5), hedging: false, TimeSpan.FromSeconds(1));
        var live = new HashSet<int> { 0, 1 };
        var lacks = new Dictionary<int, HashSet<int>> { [0] = new() { 0, 2, 4 }, [1] = new() { 1, 3 } };
        var done = new List<int>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        async Task Worker(int id)
        {
            while (true)
            {
                if (q.IsStuck(live)) return;
                var (ok, lease) = await q.NextAsync(id, cts.Token);
                if (!ok) return;
                if (lacks[id].Contains(lease.Index)) { q.Decline(lease.Index, id); continue; }
                if (q.Complete(lease.Index)) lock (done) done.Add(lease.Index);
            }
        }
        await Task.WhenAll(Worker(0), Worker(1));
        Assert.True(q.IsFinished);
        Assert.Equal(new[] { 0, 1, 2, 3, 4 }, done.OrderBy(x => x));
    }
}

public class ChunkWorkQueueCancellationTests
{
    [Fact]
    public async Task RaceCancellation_fires_when_another_fetcher_completes_the_chunk()
    {
        var q = new ChunkWorkQueue(new[] { 0 }, hedging: false, TimeSpan.FromSeconds(1));
        var lease = (await q.NextAsync(0, CancellationToken.None)).Lease;
        Assert.False(lease.RaceCancellation.IsCancellationRequested);
        q.Complete(0);
        Assert.True(lease.RaceCancellation.IsCancellationRequested);
    }

    [Fact]
    public async Task Disposed_Cts_after_Complete_does_not_throw_when_a_linked_token_source_is_created_concurrently()
    {
        // Reproduces the exact production pattern: a worker holds the lease's token and links it into a
        // per-attempt CancellationTokenSource AFTER Complete() may already have disposed the original.
        var q = new ChunkWorkQueue(new[] { 0 }, hedging: false, TimeSpan.FromSeconds(1));
        var lease = (await q.NextAsync(0, CancellationToken.None)).Lease;
        var token = lease.RaceCancellation;   // struct copy of the token, valid independent of the CTS object
        q.Complete(0);                        // this disposes the underlying CancellationTokenSource

        // Linking a token whose source was disposed must not throw (CancellationToken itself has no dispose
        // state; only CancellationTokenSource does). This is exactly what XMeshRuntime does every attempt.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None, token);
        Assert.True(linked.IsCancellationRequested);
    }

    [Fact]
    public async Task Hedge_loser_is_cancelled_the_instant_the_winner_completes()
    {
        var q = new ChunkWorkQueue(new[] { 0 }, hedging: true, TimeSpan.FromMilliseconds(50));
        var orig = (await q.NextAsync(0, CancellationToken.None)).Lease;
        await Task.Delay(100);
        var hedge = (await q.NextAsync(1, CancellationToken.None)).Lease;
        Assert.True(hedge.IsHedge);
        Assert.False(orig.RaceCancellation.IsCancellationRequested);
        Assert.False(hedge.RaceCancellation.IsCancellationRequested);

        q.Complete(hedge.Index);   // hedge wins

        Assert.True(orig.RaceCancellation.IsCancellationRequested);    // the ORIGINAL must now stop
        Assert.True(hedge.RaceCancellation.IsCancellationRequested);   // both leases share the same token
    }

    [Fact]
    public async Task Requeue_with_no_remaining_fetcher_disposes_and_the_next_taker_gets_a_fresh_token()
    {
        var q = new ChunkWorkQueue(new[] { 0 }, hedging: false, TimeSpan.FromSeconds(1));
        var first = (await q.NextAsync(0, CancellationToken.None)).Lease;
        q.Requeue(first.Index);                 // no hedge involved: this fully abandons the chunk

        var second = (await q.NextAsync(1, CancellationToken.None)).Lease;
        Assert.False(second.RaceCancellation.IsCancellationRequested);   // fresh token, not the disposed one
        q.Complete(second.Index);
        Assert.True(second.RaceCancellation.IsCancellationRequested);
    }
}
