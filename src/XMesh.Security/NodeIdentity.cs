using System.Security.Cryptography;
using XMesh.Core;

namespace XMesh.Security;

/// <summary>
/// A node's long-lived cryptographic identity (spec section 10): an ECDSA P-256 keypair.
/// NodeId = SHA-256(SPKI). Private key is persisted as PKCS#8 with owner-only permissions.
/// </summary>
public sealed class NodeIdentity : IDisposable
{
    private readonly ECDsa _key;

    public NodeId Id { get; }
    /// <summary>DER SubjectPublicKeyInfo of the public key.</summary>
    public byte[] PublicKeySpki { get; }

    private NodeIdentity(ECDsa key)
    {
        _key = key;
        PublicKeySpki = key.ExportSubjectPublicKeyInfo();
        Id = NodeId.FromPublicKey(PublicKeySpki);
    }

    public static NodeIdentity Generate() => new(ECDsa.Create(ECCurve.NamedCurves.nistP256));

    /// <summary>Load an identity from disk, creating and persisting a new one if absent.</summary>
    public static NodeIdentity LoadOrCreate(string path)
    {
        if (File.Exists(path))
        {
            var ecdsa = ECDsa.Create();
            try { ecdsa.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _); }
            catch (CryptographicException ex)
            {
                ecdsa.Dispose();
                throw new XMeshException(XMeshErrorCode.Unknown, $"Identity file '{path}' is corrupt.", ex);
            }
            return new NodeIdentity(ecdsa);
        }

        var id = Generate();
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var tmp = path + ".tmp";
        File.WriteAllBytes(tmp, id._key.ExportPkcs8PrivateKey());
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(tmp, path, overwrite: true);
        return id;
    }

    public byte[] Sign(ReadOnlySpan<byte> data) =>
        _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public static bool Verify(ReadOnlySpan<byte> spki, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        if (signature.Length != 64) return false;
        try
        {
            using var pub = ECDsa.Create();
            pub.ImportSubjectPublicKeyInfo(spki, out _);
            return pub.VerifyData(data, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException) { return false; }
    }

    public void Dispose() => _key.Dispose();
}
