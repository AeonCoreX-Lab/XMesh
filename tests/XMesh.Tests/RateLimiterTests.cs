using System.Diagnostics;
using XMesh.Core;
using Xunit;

namespace XMesh.Tests;

/// <summary>Deterministic: a fake clock and a fake delay that advances it. No real sleeping, no timing flakiness.</summary>
public class RateLimiterTests
{
    private sealed class FakeTime
    {
        public long Ticks;                                   // Stopwatch ticks
        public readonly List<TimeSpan> Waits = new();
        public long Now() => Ticks;
        public Task Delay(TimeSpan t, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Waits.Add(t);
            Ticks += (long)(t.TotalSeconds * Stopwatch.Frequency);
            return Task.CompletedTask;
        }
        public void Advance(double seconds) => Ticks += (long)(seconds * Stopwatch.Frequency);
    }

    private static (RateLimiter, FakeTime) Make(long rate)
    {
        var ft = new FakeTime();
        return (new RateLimiter(rate, ft.Now, ft.Delay), ft);
    }

    [Fact]
    public async Task Unlimited_never_waits()
    {
        var (rl, ft) = Make(0);
        await rl.AcquireAsync(long.MaxValue / 2);
        Assert.True(rl.IsUnlimited);
        Assert.Equal(0, ft.Waits.Count);
    }

    [Fact]
    public async Task Burst_up_to_one_second_of_bandwidth_is_immediate()
    {
        var (rl, ft) = Make(1000);
        await rl.AcquireAsync(1000);
        Assert.Equal(0, ft.Waits.Count);
    }

    [Fact]
    public async Task Exceeding_the_bucket_waits_exactly_the_time_to_pay_the_debt()
    {
        var (rl, ft) = Make(1000);
        await rl.AcquireAsync(1000);          // drains the bucket
        await rl.AcquireAsync(500);           // 500 bytes at 1000 B/s => 0.5 s
        Assert.Equal(1, ft.Waits.Count);
        Assert.True(Math.Abs(ft.Waits[0].TotalSeconds - 0.5) < 1e-6);
    }

    [Fact]
    public async Task Sustained_throughput_converges_to_the_configured_rate()
    {
        var (rl, ft) = Make(10_000);          // 10 KB/s
        long start = ft.Ticks;
        long total = 0;
        for (int i = 0; i < 100; i++) { await rl.AcquireAsync(1_000); total += 1_000; }   // 100 KB
        double seconds = (double)(ft.Ticks - start) / Stopwatch.Frequency;
        double rate = total / seconds;
        // 100 KB at 10 KB/s = 10 s, minus the 1 s initial burst => ~9 s => ~11.1 KB/s effective; never far above the limit.
        Assert.True(seconds >= 8.9 && seconds <= 9.1, $"expected ~9s of simulated time, got {seconds}");
        Assert.True(rate <= 11_200, $"effective rate {rate} exceeds limit + burst allowance");
    }

    [Fact]
    public async Task Idle_time_refills_but_never_beyond_one_second_of_burst()
    {
        var (rl, ft) = Make(1000);
        await rl.AcquireAsync(1000);
        ft.Advance(60);                       // idle for a minute
        Assert.True(rl.Balance <= 1000.0 + 1e-6);   // capped at one second, not 60 seconds
        await rl.AcquireAsync(1000);
        Assert.Equal(0, ft.Waits.Count);      // one second of burst available...
        await rl.AcquireAsync(1);
        Assert.Equal(1, ft.Waits.Count);      // ...but not more
    }

    [Fact]
    public async Task A_request_larger_than_the_bucket_is_allowed_and_charged_as_debt()
    {
        var (rl, ft) = Make(1000);
        await rl.AcquireAsync(5000);          // 5x the bucket: must not deadlock or throw
        Assert.Equal(1, ft.Waits.Count);
        Assert.True(Math.Abs(ft.Waits[0].TotalSeconds - 4.0) < 1e-6);   // 4000 bytes over the burst
    }

    [Fact]
    public async Task Concurrent_callers_share_one_budget_no_free_lunch()
    {
        // 20 callers x 500 B = 10,000 B against 1000 B/s with a 1000 B initial burst. Whatever the
        // interleaving, the callers together are charged for 10,000 bytes, so the summed debt they were told
        // to wait must equal the bytes beyond the burst (9,000 B => 9,000 B / 1000 B/s), give or take refill
        // that the fake clock adds while earlier waits "elapse".
        var (rl, ft) = Make(1000);
        long charged = 0;
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(async () =>
        {
            await rl.AcquireAsync(500);
            Interlocked.Add(ref charged, 500);
        })));

        Assert.Equal(10_000L, charged);                                   // every caller completed, none lost

        // The fake clock only advances when someone waits, so simulated time == total time the limiter
        // made callers wait. Free lunch would mean ~0; correct accounting means about 9 s.
        double simulatedSeconds = (double)ft.Ticks / Stopwatch.Frequency;
        Assert.True(simulatedSeconds > 4.0, $"limiter under-charged: only {simulatedSeconds:F2}s of waiting for 10 KB at 1 KB/s");
        Assert.True(simulatedSeconds < 9.5, $"limiter over-charged: {simulatedSeconds:F2}s");
        Assert.True(ft.Waits.Count >= 10, $"expected most callers to wait, only {ft.Waits.Count} did");
    }

    [Fact]
    public async Task Cancellation_is_honoured_while_waiting()
    {
        using var cts = new CancellationTokenSource();
        var rl = new RateLimiter(1, delay: (t, ct) => Task.Delay(t, ct));   // 1 B/s: a 100-byte ask waits ~99 s
        await rl.AcquireAsync(1);
        cts.CancelAfter(50);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => rl.AcquireAsync(100, cts.Token));
    }

    [Fact]
    public async Task Pre_cancelled_token_throws_without_consuming_budget()
    {
        var (rl, _) = Make(1000);
        using var cts = new CancellationTokenSource(); cts.Cancel();
        double before = rl.Balance;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => rl.AcquireAsync(500, cts.Token));
        Assert.True(Math.Abs(rl.Balance - before) < 1e-6);
    }

    [Fact]
    public async Task Negative_rate_or_size_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RateLimiter(-1));
        var (rl, _) = Make(10);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => rl.AcquireAsync(-1));
    }
}
