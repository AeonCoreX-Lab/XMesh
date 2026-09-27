using XMesh.Assets;
using XMesh.Core;

namespace XMesh.Security;

/// <summary>
/// Publisher authenticity (spec section 16/20). Chunk integrity and publisher authenticity are
/// distinct: verification here proves the manifest was signed by the key it embeds, and the
/// caller must additionally check that key against a trusted-publisher set.
/// </summary>
public static class ManifestSigner
{
    public static AssetManifest Sign(AssetManifest unsigned, NodeIdentity publisher)
    {
        var expectedKey = Convert.ToHexString(publisher.PublicKeySpki).ToLowerInvariant();
        if (unsigned.PublisherKey != expectedKey)
            throw new XMeshException(XMeshErrorCode.ManifestInvalid, "Manifest publisherKey does not match signing identity.");
        var sig = publisher.Sign(unsigned.GetSigningBytes());
        return unsigned.WithSignature(Convert.ToHexString(sig).ToLowerInvariant());
    }

    /// <summary>Verifies the signature against the key embedded in the manifest.</summary>
    public static bool VerifySignature(AssetManifest m)
    {
        if (string.IsNullOrEmpty(m.Signature)) return false;
        try
        {
            return NodeIdentity.Verify(
                Convert.FromHexString(m.PublisherKey),
                m.GetSigningBytes(),
                Convert.FromHexString(m.Signature));
        }
        catch (FormatException) { return false; }
    }

    /// <summary>Full check: structure, signature, and publisher is in the trusted set.</summary>
    public static void VerifyOrThrow(AssetManifest m, ITrustStore trust)
    {
        m.Validate();
        if (!VerifySignature(m))
            throw new XMeshException(XMeshErrorCode.ManifestSignatureInvalid,
                $"Manifest {m.AssetId}@{m.Version} has an invalid or missing signature.");
        if (!trust.IsTrustedPublisher(m.PublisherKey))
            throw new XMeshException(XMeshErrorCode.ManifestSignatureInvalid,
                $"Publisher '{m.Publisher}' is not trusted on this node.");
    }
}
