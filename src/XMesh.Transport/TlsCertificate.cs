using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace XMesh.Transport;

/// <summary>
/// Ephemeral self-signed certificate used ONLY to get an encrypted TLS 1.3 channel.
/// Trust is NOT derived from this certificate (it is not validated against any CA);
/// peer identity is established by the XMA application-layer handshake, which is why the
/// TLS validation callback accepts any certificate. This is the same model as a Noise/SSH
/// style "encrypt first, authenticate the key inside" design.
/// </summary>
internal static class TlsCertificate
{
    public static X509Certificate2 CreateEphemeral()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=xma-node", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        // Round-trip through PFX so the private key is usable by SslStream on all platforms.
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null,
            X509KeyStorageFlags.Exportable);
    }
}
