using System.Buffers;

namespace XMesh.Core;

/// <summary>
/// An owned, pooled byte buffer (spec section 23: memory pooling).
///
/// Rules that make pooling safe:
///  * <see cref="Memory"/>/<see cref="Span"/> expose exactly <see cref="Length"/> bytes, never the (larger) rented array.
///  * <see cref="Dispose"/> returns the array to the pool exactly once; later calls are no-ops.
///  * After Dispose, <see cref="Memory"/>/<see cref="Span"/> throw, so use-after-return fails loudly instead of
///    silently reading another request's data.
///  * <c>clearArray: true</c> zeroes the buffer on return; use it for anything secret.
///  * Callers that need the bytes to outlive the lease must call <see cref="ToArray"/> (an explicit copy).
/// </summary>
public sealed class PooledBuffer : IDisposable
{
    private byte[]? _array;
    private readonly bool _clear;
    private readonly ArrayPool<byte> _pool;

    private static long _outstanding;

    /// <summary>
    /// Number of buffers currently rented and not yet disposed, process-wide. A steady-state value that keeps
    /// growing means a leak. Exposed for diagnostics and leak tests.
    /// </summary>
    public static long Outstanding => Interlocked.Read(ref _outstanding);

    public int Length { get; }

    private PooledBuffer(byte[] array, int length, bool clear, ArrayPool<byte> pool)
    { _array = array; Length = length; _clear = clear; _pool = pool; }

    public static PooledBuffer Rent(int length, bool clearOnReturn = false, ArrayPool<byte>? pool = null)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        pool ??= ArrayPool<byte>.Shared;
        var b = new PooledBuffer(pool.Rent(length), length, clearOnReturn, pool);
        Interlocked.Increment(ref _outstanding);
        return b;
    }

    public Memory<byte> Memory => (_array ?? throw new ObjectDisposedException(nameof(PooledBuffer))).AsMemory(0, Length);
    public Span<byte> Span => (_array ?? throw new ObjectDisposedException(nameof(PooledBuffer))).AsSpan(0, Length);
    public bool IsDisposed => _array is null;

    /// <summary>Explicit, exact-size copy that is safe to keep after this buffer is disposed.</summary>
    public byte[] ToArray() => Span.ToArray();

    public void Dispose()
    {
        var a = Interlocked.Exchange(ref _array, null);
        if (a is null) return;                                   // already returned: idempotent
        Interlocked.Decrement(ref _outstanding);
        _pool.Return(a, _clear);
    }
}
