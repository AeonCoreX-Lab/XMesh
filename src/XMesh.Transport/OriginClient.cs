using System.Net;
using System.Net.Http.Headers;
using XMesh.Assets;
using XMesh.Core;

namespace XMesh.Transport;

/// <summary>
/// HTTP(S) origin fallback (spec section 40). Uses Range requests so individual chunks can be
/// fetched and resumed. The origin is treated as untrusted transport: every byte is still
/// verified against the signed manifest before it touches the cache.
/// </summary>
public sealed class OriginClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly bool _ownsClient;

    public OriginClient(HttpClient? http = null)
    {
        if (http is null)
        {
            var handler = new SocketsHttpHandler
            {
                AllowAutoRedirect = true,
                MaxAutomaticRedirections = 3,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            };
            _http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(60) };
            _ownsClient = true;
        }
        else _http = http;
        if (!_http.DefaultRequestHeaders.UserAgent.Any())
            _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("XMesh", "0.1"));
    }

    /// <summary>Fetch a chunk into a NEW array. Kept for compatibility; prefer <see cref="GetChunkPooledAsync"/>.</summary>
    public async Task<byte[]> GetChunkAsync(AssetManifest m, int index, CancellationToken ct)
    {
        var buf = new byte[ChunkLen(m, index)];
        await FetchIntoAsync(m, index, buf, ct).ConfigureAwait(false);
        return buf;
    }

    /// <summary>Fetch a chunk into a pooled buffer. The CALLER owns the returned buffer and must dispose it.</summary>
    public async Task<PooledBuffer> GetChunkPooledAsync(AssetManifest m, int index, CancellationToken ct)
    {
        var lease = PooledBuffer.Rent(ChunkLen(m, index));
        try
        {
            await FetchIntoAsync(m, index, lease.Memory, ct).ConfigureAwait(false);
            return lease;
        }
        catch { lease.Dispose(); throw; }                       // never leak the lease on any failure
    }

    private static int ChunkLen(AssetManifest m, int index)
    {
        if ((uint)index >= (uint)m.ChunkCount) throw new ArgumentOutOfRangeException(nameof(index));
        return m.ChunkLength(index);
    }

    /// <summary>The single implementation: fill <paramref name="dest"/> (exactly one chunk long) from the origin.</summary>
    private async Task FetchIntoAsync(AssetManifest m, int index, Memory<byte> dest, CancellationToken ct)
    {
        if (m.Origin is null)
            throw new XMeshException(XMeshErrorCode.OriginUnavailable, "Manifest declares no origin.");

        long start = (long)index * m.ChunkSize;
        int len = m.ChunkLength(index);
        if (dest.Length != len) throw new ArgumentException("Destination must be exactly one chunk long.", nameof(dest));
        long end = start + len - 1;

        using var req = new HttpRequestMessage(HttpMethod.Get, m.Origin);
        req.Headers.Range = new RangeHeaderValue(start, end);

        HttpResponseMessage resp;
        try { resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false); }
        catch (HttpRequestException ex) { throw new XMeshException(XMeshErrorCode.OriginUnavailable, $"Origin request failed: {ex.Message}", ex); }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        { throw new XMeshException(XMeshErrorCode.OriginUnavailable, "Origin request timed out.", ex); }

        using (resp)
        {
            if (resp.StatusCode == HttpStatusCode.PartialContent)
            {
                await using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await ReadFullAsync(body, dest, ct).ConfigureAwait(false);
                return;
            }
            if (resp.StatusCode == HttpStatusCode.OK)
            {
                // Server ignored Range and is sending the whole object. Skip to the offset and read one chunk.
                await using var body = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                await SkipAsync(body, start, ct).ConfigureAwait(false);
                await ReadFullAsync(body, dest, ct).ConfigureAwait(false);
                return;
            }
            throw new XMeshException(XMeshErrorCode.OriginUnavailable, $"Origin returned HTTP {(int)resp.StatusCode}.");
        }
    }

    /// <summary>A short body is an origin failure (retryable), not an unhandled EndOfStreamException.</summary>
    private static async Task ReadFullAsync(Stream body, Memory<byte> dest, CancellationToken ct)
    {
        try { await body.ReadExactlyAsync(dest, ct).ConfigureAwait(false); }
        catch (EndOfStreamException ex)
        { throw new XMeshException(XMeshErrorCode.OriginUnavailable, "Origin sent fewer bytes than requested.", ex); }
    }

    private static async Task SkipAsync(Stream s, long count, CancellationToken ct)
    {
        var scratch = new byte[81920];
        while (count > 0)
        {
            int n = await s.ReadAsync(scratch.AsMemory(0, (int)Math.Min(scratch.Length, count)), ct).ConfigureAwait(false);
            if (n == 0) throw new XMeshException(XMeshErrorCode.OriginUnavailable, "Origin ended before requested range.");
            count -= n;
        }
    }

    public void Dispose() { if (_ownsClient) _http.Dispose(); }
}
