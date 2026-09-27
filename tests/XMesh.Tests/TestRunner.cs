using System.Diagnostics;
using System.Reflection;
using Xunit;

namespace XMesh.Tests;

/// <summary>
/// Minimal test runner. Usage:  dotnet run --project tests/XMesh.Tests -- [filter] [--list]
///   filter : substring matched against "Class.Method" (case-insensitive)
/// Exit code 0 = all passed, 1 = at least one failure, 2 = nothing matched.
/// </summary>
public static class TestRunner
{
    private static readonly TimeSpan PerTestTimeout = TimeSpan.FromSeconds(60);

    private sealed record TestCase(Type Type, MethodInfo Method, object?[] Args, string Display);

    public static async Task<int> Main(string[] args)
    {
        bool list = args.Contains("--list");
        string? filter = args.FirstOrDefault(a => !a.StartsWith("--"));

        var cases = Discover().Where(c => filter is null ||
            c.Display.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();

        if (cases.Count == 0) { Console.WriteLine("no tests matched."); return 2; }
        if (list) { foreach (var c in cases) Console.WriteLine(c.Display); return 0; }

        int passed = 0, failed = 0;
        var failures = new List<(string, string)>();
        var total = Stopwatch.StartNew();

        foreach (var c in cases)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                await RunOne(c).WaitAsync(PerTestTimeout).ConfigureAwait(false);
                passed++;
                Console.WriteLine($"  PASS  {c.Display}  ({sw.ElapsedMilliseconds} ms)");
            }
            catch (Exception ex)
            {
                failed++;
                var root = ex is TargetInvocationException { InnerException: { } inner } ? inner : ex;
                var msg = root is TimeoutException ? $"timed out after {PerTestTimeout.TotalSeconds}s" : root.ToString();
                failures.Add((c.Display, msg));
                Console.WriteLine($"  FAIL  {c.Display}  ({sw.ElapsedMilliseconds} ms)");
            }
        }

        Console.WriteLine();
        foreach (var (name, msg) in failures)
        {
            Console.WriteLine($"--- FAILED: {name}");
            Console.WriteLine(msg);
            Console.WriteLine();
        }
        Console.WriteLine($"Total: {cases.Count}  Passed: {passed}  Failed: {failed}  ({total.Elapsed.TotalSeconds:F1}s)");
        return failed == 0 ? 0 : 1;
    }

    private static IEnumerable<TestCase> Discover()
    {
        foreach (var type in typeof(TestRunner).Assembly.GetTypes().Where(t => t.IsClass && t.IsPublic && !t.IsAbstract))
        foreach (var m in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
        {
            if (m.GetCustomAttribute<FactAttribute>() is not null)
            {
                yield return new TestCase(type, m, Array.Empty<object?>(), $"{type.Name}.{m.Name}");
            }
            else if (m.GetCustomAttribute<TheoryAttribute>() is not null)
            {
                foreach (var d in m.GetCustomAttributes<InlineDataAttribute>())
                {
                    var args = Coerce(m, d.Data);
                    yield return new TestCase(type, m, args,
                        $"{type.Name}.{m.Name}({string.Join(", ", d.Data.Select(x => x is string s ? $"\"{s}\"" : x?.ToString() ?? "null"))})");
                }
            }
        }
    }

    /// <summary>Convert InlineData values to the parameter types (e.g. int literal -> long).</summary>
    private static object?[] Coerce(MethodInfo m, object?[] data)
    {
        var ps = m.GetParameters();
        var res = new object?[data.Length];
        for (int i = 0; i < data.Length; i++)
            res[i] = data[i] is null || i >= ps.Length ? data[i] : Convert.ChangeType(data[i], ps[i].ParameterType);
        return res;
    }

    private static async Task RunOne(TestCase c)
    {
        // xunit semantics: a fresh instance of the test class per test.
        var instance = Activator.CreateInstance(c.Type);
        try
        {
            var result = c.Method.Invoke(instance, c.Args);
            if (result is Task t) await t.ConfigureAwait(false);
        }
        finally { (instance as IDisposable)?.Dispose(); }
    }
}
