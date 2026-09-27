using System.Diagnostics;

namespace XMesh.Runtime;

/// <summary>
/// Hands out chunk indices to download workers and, when the queue runs dry while some chunks are still
/// being fetched by SLOW workers, lets an idle worker "hedge" by fetching the oldest in-flight chunk too
/// (spec section 41: "Peer A slows down -> move pending chunks to Peer B").
///
/// Invariants (each is covered by a test):
///  * A chunk is never reported complete twice; the first <see cref="Complete"/> wins.
///  * A chunk that is Failed goes back to the pending set and is handed out again.
///  * Hedging only starts a duplicate for a chunk that is not already hedged, and never for the worker that
///    already holds it. So each chunk has at most 2 concurrent fetchers.
///  * Once every chunk is complete, <see cref="Next"/> returns false for everyone (workers can exit).
/// The type is fully thread-safe; time is injectable so tests need no real sleeping.
/// </summary>
public sealed class ChunkWorkQueue
{
    public readonly record struct Lease(int Index, bool IsHedge, CancellationToken RaceCancellation);

    private sealed class InFlight
    {
        public required long StartedTicks;
        public required int Owner;          // worker id that first took it
        public bool Hedged;
        /// <summary>
        /// Cancelled the instant ANY fetcher of this chunk completes it. Without this, a hedge that wins the
        /// race leaves the ORIGINAL (now-redundant) fetch running for as long as its slow transfer takes -
        /// the whole point of hedging is defeated if the loser is never told to stop. Callers pass this token
        /// into their chunk fetch and must observe it (network reads only cancel between reads otherwise).
        /// </summary>
        public readonly CancellationTokenSource Cts = new();
    }

    private readonly object _lock = new();
    private readonly Queue<int> _pending;
    private readonly Dictionary<int, InFlight> _inFlight = new();
    private readonly HashSet<int> _done = new();
    // chunk index -> workers whose peer does NOT have it. A declining worker is never offered that chunk again.
    private readonly Dictionary<int, HashSet<int>> _declined = new();
    private readonly int _total;
    private readonly TimeSpan _hedgeAfter;
    private readonly bool _hedgingEnabled;
    private readonly Func<long> _now;
    private readonly SemaphoreSlim _signal = new(0);

    public ChunkWorkQueue(IEnumerable<int> chunks, bool hedging, TimeSpan hedgeAfter, Func<long>? nowTicks = null)
    {
        _pending = new Queue<int>(chunks);
        _total = _pending.Count;
        _hedgingEnabled = hedging;
        _hedgeAfter = hedgeAfter;
        _now = nowTicks ?? (() => Stopwatch.GetTimestamp());
    }

    public int Remaining { get { lock (_lock) return _total - _done.Count; } }
    public bool IsFinished { get { lock (_lock) return _done.Count == _total; } }

    /// <summary>Total duplicate (hedge) fetches started. For metrics and tests.</summary>
    public int HedgesStarted { get { lock (_lock) return _hedges; } }
    private int _hedges;

    /// <summary>
    /// Get the next chunk for <paramref name="worker"/> to fetch. Waits while nothing is available but work
    /// remains; returns false when all chunks are complete or the token is cancelled.
    /// </summary>
    public async Task<(bool Ok, Lease Lease)> NextAsync(int worker, CancellationToken ct)
    {
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            TimeSpan? wait = null;
            lock (_lock)
            {
                if (_done.Count == _total) return (false, default);

                // Take the first pending chunk this worker has not declined. Chunks it declined stay queued for
                // other workers (re-enqueued below in order), so declining can never cause an offer/decline spin.
                // A chunk THIS worker declined and that is not in flight anywhere else is dropped from _pending
                // entirely if every OTHER outstanding worker has also declined it (nobody left who could serve it);
                // that pruning is what lets the "nothing left for me" check below ever see an empty queue.
                int pendingCount = _pending.Count;
                List<int>? skipped = null;
                int chosen = -1;
                for (int n = 0; n < pendingCount; n++)
                {
                    var idx = _pending.Dequeue();
                    if (_done.Contains(idx)) continue;                       // finished by a hedge meanwhile
                    if (chosen < 0 && !HasDeclined(idx, worker)) { chosen = idx; continue; }
                    (skipped ??= new List<int>()).Add(idx);
                }
                // Restore the not-chosen chunks AHEAD of nothing else: original relative order is preserved.
                if (skipped is not null) foreach (var k in skipped) _pending.Enqueue(k);
                if (chosen >= 0)
                {
                    _inFlight[chosen] = new InFlight { StartedTicks = _now(), Owner = worker };
                    return (true, new Lease(chosen, false, _inFlight[chosen].Cts.Token));
                }

                // Nothing left this worker could take: everything still pending is something IT declined
                // (checked directly, not via _pending.Count, since declined chunks stay queued for other
                // workers). Without this, a lone worker whose peer lacks some chunks spins on NextAsync
                // forever after finishing everything it could, instead of telling the caller to fall back.
                if (!_inFlight.Values.Any(f => f.Owner == worker) &&
                    _pending.All(idx => HasDeclined(idx, worker)) &&
                    AllUnfinishedDeclinedBy(worker))
                {
                    return (false, default);
                }

                if (_hedgingEnabled)
                {
                    // Oldest in-flight chunk that nobody has hedged and that this worker does not already hold.
                    int best = -1; long bestStart = long.MaxValue;
                    foreach (var (idx, f) in _inFlight)
                        if (!f.Hedged && f.Owner != worker && !HasDeclined(idx, worker) && f.StartedTicks < bestStart) { best = idx; bestStart = f.StartedTicks; }

                    if (best >= 0)
                    {
                        var age = TimeSpan.FromSeconds((double)(_now() - bestStart) / Stopwatch.Frequency);
                        if (age >= _hedgeAfter)
                        {
                            _inFlight[best].Hedged = true;
                            _hedges++;
                            return (true, new Lease(best, true, _inFlight[best].Cts.Token));
                        }
                        wait = _hedgeAfter - age;                            // check again when it becomes hedge-worthy
                    }
                }
            }

            // Nothing to hand out right now. Wake on any state change, or when a hedge becomes due.
            var timeout = wait is { } w && w > TimeSpan.Zero ? w : TimeSpan.FromMilliseconds(200);
            try { await _signal.WaitAsync(timeout, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
        }
    }

    /// <summary>Mark a chunk finished. Returns true only for the FIRST completion (the winner).</summary>
    public bool Complete(int index)
    {
        bool first;
        CancellationTokenSource? cts = null;
        lock (_lock)
        {
            first = _done.Add(index);
            if (_inFlight.TryGetValue(index, out var f)) { cts = f.Cts; _inFlight.Remove(index); }
        }
        // Cancel OUTSIDE the lock (cancellation callbacks can run synchronously and must never re-enter it).
        // This is what makes a losing hedge (or a losing original, if the hedge wins) stop immediately
        // instead of running its slow transfer to completion for no reason.
        cts?.Cancel();
        cts?.Dispose();
        Wake();
        return first;
    }

    /// <summary>
    /// A fetch attempt ended without completing the chunk. If it was a hedge, just release the hedge slot; if it
    /// was the original owner and nobody else is fetching it, return the chunk to the pending set.
    /// </summary>
    public void Failed(int index, bool wasHedge)
    {
        lock (_lock)
        {
            if (_done.Contains(index)) { _inFlight.Remove(index); Wake(); return; }
            if (wasHedge)
            {
                // The original owner is presumably still trying. Allow a future hedge again.
                if (_inFlight.TryGetValue(index, out var f)) f.Hedged = false;
            }
            else
            {
                // Original owner gave up. If a hedge is running, it now IS the only fetcher: keep it in flight
                // (owner -1 = nobody specific) so it can still be handed to a third worker if it stalls too.
                if (_inFlight.TryGetValue(index, out var f) && f.Hedged) { f.Owner = -1; f.Hedged = false; f.StartedTicks = _now(); }
                else { _inFlight.Remove(index); _pending.Enqueue(index); }
            }
        }
        Wake();
    }


    private bool HasDeclined(int index, int worker) => _declined.TryGetValue(index, out var w) && w.Contains(worker);

    /// <summary>True if every currently-unfinished chunk has been declined by this specific worker.</summary>
    private bool AllUnfinishedDeclinedBy(int worker)
    {
        int unfinished = _total - _done.Count;
        int declinedByThisWorker = _declined.Count(kv => !_done.Contains(kv.Key) && kv.Value.Contains(worker));
        return unfinished > 0 && declinedByThisWorker == unfinished;
    }

    /// <summary>
    /// A chunk is unservable only if it was declined by EVERY worker in <paramref name="liveWorkers"/> - the
    /// workers still actually able to try it. Counting declines by ID (not by a bare integer count) is required:
    /// a worker that already exited (having declined chunks on its way out) must not "count" toward stuck-ness
    /// for the survivors, or a survivor that never even saw the chunk gets wrongly told to give up on it.
    /// </summary>
    private bool IsUnservableByAll(int index, IReadOnlySet<int> liveWorkers) =>
        _declined.TryGetValue(index, out var declinedBy) && liveWorkers.All(w => declinedBy.Contains(w));

    /// <summary>
    /// This worker's peer does not have <paramref name="index"/>. The chunk goes back for OTHER workers, and this
    /// worker will never be offered it again (fixes an offer/requeue infinite loop).
    /// </summary>
    public void Decline(int index, int worker, bool wasHedge = false)
    {
        lock (_lock)
        {
            if (!_declined.TryGetValue(index, out var set)) _declined[index] = set = new HashSet<int>();
            set.Add(worker);
        }
        Requeue(index, wasHedge);
    }

    /// <summary>
    /// True when work remains but NONE of the workers in <paramref name="liveWorkers"/> can make progress on it:
    /// every unfinished chunk has been declined by all of them (or is being served in a hedge only they would
    /// duplicate). Callers should stop and fall back (e.g. to the origin). Pass the SET of still-alive worker
    /// ids, not a count - see <see cref="IsUnservableByAll"/> for why an exited worker must not be counted.
    /// </summary>
    public bool IsStuck(IReadOnlySet<int> liveWorkers)
    {
        lock (_lock)
        {
            if (_done.Count == _total) return false;
            int unfinished = _total - _done.Count;
            int unservable = 0;
            foreach (var idx in AllUnfinishedIndices())
                if (IsUnservableByAll(idx, liveWorkers)) unservable++;
            return unfinished > 0 && unservable == unfinished;
        }
    }

    /// <summary>Unfinished chunks that every worker in <paramref name="liveWorkers"/> has declined.</summary>
    public IEnumerable<int> Unservable(IReadOnlySet<int> liveWorkers)
    {
        lock (_lock) return AllUnfinishedIndices().Where(idx => IsUnservableByAll(idx, liveWorkers)).ToList();
    }

    private IEnumerable<int> AllUnfinishedIndices()
    {
        for (int i = 0; i < _total; i++) if (!_done.Contains(i)) yield return i;
    }

    /// <summary>
    /// Give a chunk back for OTHER workers to take (this worker cannot serve it).
    /// If another worker is already fetching it (a hedge is running), that fetch is now the only one:
    /// do NOT also put it back in the pending queue, or a third worker would start a redundant copy.
    /// </summary>
    public void Requeue(int index, bool wasHedge = false)
    {
        CancellationTokenSource? cts = null;
        lock (_lock)
        {
            if (_done.Contains(index)) return;
            if (_inFlight.TryGetValue(index, out var f) && f.Hedged)
            {
                if (wasHedge) { f.Hedged = false; }                          // hedge gave up; original keeps going
                else { f.Owner = -1; f.Hedged = false; f.StartedTicks = _now(); }   // original gave up; hedge is now sole fetcher
                Wake();
                return;
            }
            if (_inFlight.TryGetValue(index, out var dying)) cts = dying.Cts;
            _inFlight.Remove(index);
            _pending.Enqueue(index);
        }
        // This chunk has no fetcher left at all right now: its old race-cancellation token is done. Dispose it;
        // the NEXT worker to take the chunk gets a brand-new InFlight with a fresh Cts.
        cts?.Dispose();
        Wake();
    }

    private void Wake() { try { _signal.Release(); } catch (SemaphoreFullException) { } }
}
