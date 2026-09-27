// A dependency-free, xunit-compatible micro test framework.
//
// Why this exists: the build environment for this project can be fully offline, and pulling
// xunit from NuGet would break that. Only the tiny surface actually used by the tests is
// implemented ([Fact], [Theory]+[InlineData], and the Assert methods below), and it lives in
// namespace Xunit so every test file compiles unchanged against real xunit as well.
//
// To switch to real xunit later: delete this file and TestRunner.cs, add the xunit.v3 package
// references, and set <OutputType>Exe</OutputType> per xunit.v3's own guidance.
using System.Collections;
using System.Runtime.CompilerServices;

namespace Xunit;

[AttributeUsage(AttributeTargets.Method)]
public sealed class FactAttribute : Attribute { }

[AttributeUsage(AttributeTargets.Method)]
public sealed class TheoryAttribute : Attribute { }

[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class InlineDataAttribute : Attribute
{
    public object?[] Data { get; }
    public InlineDataAttribute(params object?[] data) => Data = data;
}

public class XunitException : Exception
{
    public XunitException(string message) : base(message) { }
}

public static class Assert
{
    public static void True(bool condition, string? message = null)
    {
        if (!condition) throw new XunitException(message ?? "Assert.True() failure: expected true, got false.");
    }

    public static void False(bool condition, string? message = null)
    {
        if (condition) throw new XunitException(message ?? "Assert.False() failure: expected false, got true.");
    }

    public static void Null(object? value)
    {
        if (value is not null) throw new XunitException($"Assert.Null() failure: got {Fmt(value)}.");
    }

    public static void Empty<T>(IEnumerable<T> collection)
    {
        if (collection.Any()) throw new XunitException($"Assert.Empty() failure: collection had {collection.Count()} element(s): {Fmt(collection)}");
    }

    public static void NotNull(object? value)
    {
        if (value is null) throw new XunitException("Assert.NotNull() failure: value was null.");
    }

    public static void Equal<T>(T expected, T actual)
    {
        if (!DeepEquals(expected, actual))
            throw new XunitException($"Assert.Equal() failure:\n  expected: {Fmt(expected)}\n  actual  : {Fmt(actual)}");
    }

    /// <summary>xunit-style: compare two sequences element by element even if their static types differ.</summary>
    public static void Equal<T>(IEnumerable<T> expected, IEnumerable<T> actual)
    {
        if (!DeepEquals(expected, actual))
            throw new XunitException($"Assert.Equal() failure:\n  expected: {Fmt(expected)}\n  actual  : {Fmt(actual)}");
    }

    public static void Equal(int expected, long actual) => Equal<long>(expected, actual);
    public static void Equal(long expected, int actual) => Equal<long>(expected, actual);

    public static void Contains<T>(IEnumerable<T> collection, Func<T, bool> predicate)
    {
        foreach (var x in collection) if (predicate(x)) return;
        throw new XunitException("Assert.Contains() failure: no element matched the predicate.");
    }

    public static void Contains<T>(T expected, IEnumerable<T> collection)
    {
        foreach (var x in collection) if (DeepEquals(expected, x)) return;
        throw new XunitException($"Assert.Contains() failure: {Fmt(expected)} not found.");
    }

    public static void DoesNotContain<T>(IEnumerable<T> collection, Func<T, bool> predicate)
    {
        foreach (var x in collection)
            if (predicate(x)) throw new XunitException($"Assert.DoesNotContain() failure: matched {Fmt(x)}.");
    }

    public static void All<T>(IEnumerable<T> collection, Action<T> action)
    {
        int i = 0;
        foreach (var x in collection)
        {
            try { action(x); }
            catch (XunitException ex) { throw new XunitException($"Assert.All() failure at index {i}: {ex.Message}"); }
            i++;
        }
    }

    // ---- exceptions ------------------------------------------------------------------

    /// <summary>xunit semantics: the thrown type must match EXACTLY (not a subclass).</summary>
    public static T Throws<T>(Action code) where T : Exception
    {
        try { code(); }
        catch (Exception ex)
        {
            if (ex.GetType() == typeof(T)) return (T)ex;
            throw new XunitException($"Assert.Throws() failure: expected {typeof(T).Name}, got {ex.GetType().Name}: {ex.Message}");
        }
        throw new XunitException($"Assert.Throws() failure: expected {typeof(T).Name}, but no exception was thrown.");
    }

    public static async Task<T> ThrowsAsync<T>(Func<Task> code) where T : Exception
    {
        try { await code().ConfigureAwait(false); }
        catch (Exception ex)
        {
            if (ex.GetType() == typeof(T)) return (T)ex;
            throw new XunitException($"Assert.ThrowsAsync() failure: expected {typeof(T).Name}, got {ex.GetType().Name}: {ex.Message}");
        }
        throw new XunitException($"Assert.ThrowsAsync() failure: expected {typeof(T).Name}, but no exception was thrown.");
    }

    public static async Task<T> ThrowsAsync<T, TResult>(Func<Task<TResult>> code) where T : Exception =>
        await ThrowsAsync<T>(async () => { await code().ConfigureAwait(false); }).ConfigureAwait(false);

    /// <summary>Any exception assignable to T (including subclasses).</summary>
    public static async Task<T> ThrowsAnyAsync<T>(Func<Task> code) where T : Exception
    {
        try { await code().ConfigureAwait(false); }
        catch (Exception ex)
        {
            if (ex is T t) return t;
            throw new XunitException($"Assert.ThrowsAnyAsync() failure: expected {typeof(T).Name}, got {ex.GetType().Name}.");
        }
        throw new XunitException($"Assert.ThrowsAnyAsync() failure: expected {typeof(T).Name}, but no exception was thrown.");
    }

    // ---- structural equality ----------------------------------------------------------

    private static bool DeepEquals(object? a, object? b)
    {
        if (ReferenceEquals(a, b)) return true;
        if (a is null || b is null) return false;

        if (a is byte[] ba && b is byte[] bb) return ba.AsSpan().SequenceEqual(bb);

        if (a is string || b is string) return a.Equals(b);

        if (a is IEnumerable ea && b is IEnumerable eb && a is not ITuple && b is not ITuple)
        {
            var ia = ea.GetEnumerator(); var ib = eb.GetEnumerator();
            while (true)
            {
                bool ma = ia.MoveNext(), mb = ib.MoveNext();
                if (ma != mb) return false;
                if (!ma) return true;
                if (!DeepEquals(ia.Current, ib.Current)) return false;
            }
        }
        return a.Equals(b);
    }

    private static string Fmt(object? v) => v switch
    {
        null => "null",
        byte[] b => b.Length <= 32 ? $"byte[{b.Length}] {Convert.ToHexString(b)}" : $"byte[{b.Length}] {Convert.ToHexString(b.AsSpan(0, 32))}...",
        string s => $"\"{s}\"",
        IEnumerable e => "[" + string.Join(", ", e.Cast<object?>().Take(12).Select(Fmt)) + "]",
        _ => v.ToString() ?? "?",
    };
}

// Bring System.Runtime.CompilerServices.ITuple into scope for DeepEquals.
file static class _Usings { }
