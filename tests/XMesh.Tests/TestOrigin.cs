using System.Net;

namespace XMesh.Tests;

/// <summary>Minimal HTTP origin honouring Range requests, counting every request.</summary>
internal sealed class TestOrigin : IDisposable
{
    private readonly HttpListener _l = new();
    private readonly byte[] _data;
    private readonly CancellationTokenSource _cts = new();
    private int _count;
    public string Url { get; }
    public int RequestCount => Volatile.Read(ref _count);

    public TestOrigin(byte[] data)
    {
        _data = data;
        int port;
        while (true)
        {
            var probe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0); probe.Start();
            port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
            try { _l.Prefixes.Clear(); _l.Prefixes.Add($"http://127.0.0.1:{port}/"); _l.Start(); break; }
            catch (HttpListenerException) { }
        }
        Url = $"http://127.0.0.1:{port}/asset.bin";
        _ = Task.Run(LoopAsync);
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext c;
            try { c = await _l.GetContextAsync(); } catch { return; }
            Interlocked.Increment(ref _count);
            try
            {
                var range = c.Request.Headers["Range"];
                long start = 0, end = _data.Length - 1;
                bool partial = false;
                if (range is not null && range.StartsWith("bytes="))
                {
                    var parts = range[6..].Split('-');
                    start = long.Parse(parts[0]);
                    if (parts.Length > 1 && parts[1].Length > 0) end = Math.Min(long.Parse(parts[1]), _data.Length - 1);
                    partial = true;
                }
                int len = (int)(end - start + 1);
                c.Response.StatusCode = partial ? 206 : 200;
                c.Response.ContentLength64 = len;
                await c.Response.OutputStream.WriteAsync(_data.AsMemory((int)start, len));
            }
            catch { }
            finally { try { c.Response.Close(); } catch { } }
        }
    }

    public void Dispose() { _cts.Cancel(); try { _l.Stop(); _l.Close(); } catch { } }
}
