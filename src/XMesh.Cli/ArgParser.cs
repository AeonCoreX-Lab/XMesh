namespace XMesh.Cli;

/// <summary>Thrown for user errors (bad flags, missing arguments). Printed without a stack trace.</summary>
public sealed class UsageException : Exception
{
    public UsageException(string message) : base(message) { }
}

/// <summary>
/// Tiny, dependency-free argument parser (no NuGet packages required).
/// Supports: --flag, --opt value, --opt=value, -o value, repeatable options, positional
/// arguments, and "--" to end option parsing. Unknown options are an error (never silently ignored).
/// </summary>
public sealed class ParsedArgs
{
    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);
    public List<string> Positionals { get; } = new();

    public bool Flag(string name) => _flags.Contains(name);

    public string? Get(string name) => _values.TryGetValue(name, out var v) ? v[^1] : null;

    public IReadOnlyList<string> GetAll(string name) =>
        _values.TryGetValue(name, out var v) ? v : Array.Empty<string>();

    public string Require(string name) =>
        Get(name) ?? throw new UsageException($"missing required option --{name}");

    public int GetInt(string name, int fallback)
    {
        var s = Get(name);
        if (s is null) return fallback;
        return int.TryParse(s, out var n) ? n : throw new UsageException($"--{name} expects an integer, got '{s}'");
    }

    public string Positional(int index, string label) =>
        index < Positionals.Count ? Positionals[index] : throw new UsageException($"missing argument <{label}>");

    internal void AddValue(string name, string value)
    {
        if (!_values.TryGetValue(name, out var l)) _values[name] = l = new List<string>();
        l.Add(value);
    }
    internal void AddFlag(string name) => _flags.Add(name);
}

/// <summary>Declares which options a command accepts so parsing can be strict.</summary>
public sealed class OptionSpec
{
    public string Long { get; }
    public char? Short { get; }
    public bool TakesValue { get; }
    public string Description { get; }
    public OptionSpec(string @long, char? @short, bool takesValue, string description)
    { Long = @long; Short = @short; TakesValue = takesValue; Description = description; }
}

public static class ArgParser
{
    public static ParsedArgs Parse(IReadOnlyList<string> args, IReadOnlyList<OptionSpec> specs)
    {
        var byLong = specs.ToDictionary(s => s.Long, StringComparer.Ordinal);
        var byShort = specs.Where(s => s.Short.HasValue).ToDictionary(s => s.Short!.Value);
        var res = new ParsedArgs();

        for (int i = 0; i < args.Count; i++)
        {
            var a = args[i];

            if (a == "--") { for (i++; i < args.Count; i++) res.Positionals.Add(args[i]); break; }

            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                string name = a[2..];
                string? inline = null;
                int eq = name.IndexOf('=');
                if (eq >= 0) { inline = name[(eq + 1)..]; name = name[..eq]; }

                if (!byLong.TryGetValue(name, out var spec)) throw new UsageException($"unknown option --{name}");
                Apply(res, spec, inline, args, ref i);
            }
            else if (a.Length >= 2 && a[0] == '-' && !char.IsDigit(a[1]))
            {
                if (a.Length != 2) throw new UsageException($"unknown option {a} (short options take one letter, e.g. -o value)");
                if (!byShort.TryGetValue(a[1], out var spec)) throw new UsageException($"unknown option {a}");
                Apply(res, spec, null, args, ref i);
            }
            else res.Positionals.Add(a);
        }
        return res;
    }

    private static void Apply(ParsedArgs res, OptionSpec spec, string? inline, IReadOnlyList<string> args, ref int i)
    {
        if (!spec.TakesValue)
        {
            if (inline is not null) throw new UsageException($"option --{spec.Long} does not take a value");
            res.AddFlag(spec.Long);
            return;
        }
        if (inline is not null) { res.AddValue(spec.Long, inline); return; }
        if (i + 1 >= args.Count) throw new UsageException($"option --{spec.Long} requires a value");
        res.AddValue(spec.Long, args[++i]);
    }

    public static string Usage(string command, IReadOnlyList<OptionSpec> specs, string positionals = "")
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"usage: xma {command} {positionals}".TrimEnd());
        foreach (var s in specs)
        {
            var shortPart = s.Short.HasValue ? $"-{s.Short}, " : "    ";
            var v = s.TakesValue ? " <value>" : "";
            sb.AppendLine($"  {shortPart}--{s.Long}{v,-9}  {s.Description}");
        }
        return sb.ToString();
    }
}
