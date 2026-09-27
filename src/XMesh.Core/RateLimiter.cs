using System.Diagnostics;

namespace XMesh.Core;

/// <summary>
/// Token-bucket bandwidth limiter (spec section 24: resource limits).
///
/// Tokens are bytes. The bucket refills continuously at <c>bytesPerSecond</c> and holds at most one
/// second of burst. A caller asks for N bytes and is delayed until they are available. A request larger
/// than the bucket capacity is allowed and simply drives the balance negative (so later callers wait the
/// debt off) - otherwise a single chunk larger than one second of bandwidth could never be sent.
///
/// Thread-safe. Time comes from an injectable clock so behaviour is testable without real sleeping.
/// A rate of 0 means unlimited (no delay, no bookkeeping).
/// </summary>
public sealed class RateLimiter
{
    private readonly object _lock = new();
    private readonly long _bytesPerSecond;
    private readonly double _capacity;
    private readonly Func<long> _nowTicks;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;
    private double _tokens;
    private long _lastTicks;

    public long BytesPerSecond => _bytesPerSecond;
    public bool IsUnlimited => _bytesPerSecond == 0;

    public RateLimiter(long bytesPerSecond, Func<long>? nowTicks = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        if (bytesPerSecond < 0) throw new ArgumentOutOfRangeException(nameof(bytesPerSecond));
        _bytesPerSecond = bytesPerSecond;
        _capacity = bytesPerSecond;                       // one second of burst
        _nowTicks = nowTicks ?? (() => Stopwatch.GetTimestamp());
        _delay = delay ?? ((t, ct) => Task.Delay(t, ct));
        _tokens = _capacity;
        _lastTicks = _nowTicks();
    }

    /// <summary>Wait until <paramref name="bytes"/> may be transferred. Returns immediately if unlimited.</summary>
    public async Task AcquireAsync(long bytes, CancellationToken ct = default)
    {
        if (bytes < 0) throw new ArgumentOutOfRangeException(nameof(bytes));
        if (_bytesPerSecond == 0 || bytes == 0) return;
        ct.ThrowIfCancellationRequested();

        TimeSpan wait;
        lock (_lock)
        {
            Refill();
            _tokens -= bytes;                              // may go negative: that is the debt others wait off
            wait = _tokens >= 0 ? TimeSpan.Zero : TimeSpan.FromSeconds(-_tokens / _bytesPerSecond);
        }
        if (wait > TimeSpan.Zero) await _delay(wait, ct).ConfigureAwait(false);
    }

    private void Refill()
    {
        long now = _nowTicks();
        double elapsed = (double)(now - _lastTicks) / Stopwatch.Frequency;
        if (elapsed <= 0) return;
        _lastTicks = now;
        _tokens = Math.Min(_capacity, _tokens + elapsed * _bytesPerSecond);
    }

    /// <summary>Current balance in bytes (negative = in debt). For diagnostics and tests.</summary>
    public double Balance { get { lock (_lock) { Refill(); return _tokens; } } }
}
