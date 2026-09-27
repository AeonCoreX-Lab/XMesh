using XMesh.Assets;
using XMesh.Core;
using XMesh.Security;
using Xunit;

namespace XMesh.Tests;

public class ManifestTests
{
    [Fact]
    public void Signed_manifest_verifies()
    {
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(Fixture.RandomBytes(10_000), pub);
        Assert.True(ManifestSigner.VerifySignature(m));
    }

    [Fact]
    public void Tampering_with_any_signed_field_breaks_signature()
    {
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(Fixture.RandomBytes(10_000), pub);

        var tamperedChunks = m.Chunks.ToList();
        tamperedChunks[0] = new string('0', 64);
        var t1 = new AssetManifest { AssetId = m.AssetId, Version = m.Version, Size = m.Size, ChunkSize = m.ChunkSize,
            Chunks = tamperedChunks, Publisher = m.Publisher, PublisherKey = m.PublisherKey, Signature = m.Signature };
        Assert.False(ManifestSigner.VerifySignature(t1));

        var t2 = new AssetManifest { AssetId = m.AssetId, Version = "9.9", Size = m.Size, ChunkSize = m.ChunkSize,
            Chunks = m.Chunks, Publisher = m.Publisher, PublisherKey = m.PublisherKey, Signature = m.Signature };
        Assert.False(ManifestSigner.VerifySignature(t2));

        var t3 = new AssetManifest { AssetId = m.AssetId, Version = m.Version, Size = m.Size, ChunkSize = m.ChunkSize,
            Chunks = m.Chunks, Publisher = m.Publisher, PublisherKey = m.PublisherKey, Origin = "http://evil.example/x", Signature = m.Signature };
        Assert.False(ManifestSigner.VerifySignature(t3));
    }

    [Fact]
    public void Untrusted_publisher_is_rejected_even_with_valid_signature()
    {
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(Fixture.RandomBytes(5000), pub);
        var trust = new MemoryTrustStore(); // trusts nobody
        var ex = Assert.Throws<XMeshException>(() => ManifestSigner.VerifyOrThrow(m, trust));
        Assert.Equal(XMeshErrorCode.ManifestSignatureInvalid, ex.Code);

        trust.TrustPublisher(Fixture.Hex(pub.PublicKeySpki));
        ManifestSigner.VerifyOrThrow(m, trust);
    }

    [Theory]
    [InlineData("../evil")]
    [InlineData("a/b")]
    [InlineData("a\\b")]
    [InlineData("..")]
    [InlineData(".hidden")]
    [InlineData("")]
    [InlineData("has space")]
    public void Path_like_asset_ids_are_rejected(string bad)
    {
        using var pub = NodeIdentity.Generate();
        var m = new AssetManifest { AssetId = bad, Version = "1", Size = 0, ChunkSize = 4096, Chunks = new(),
            Publisher = "p", PublisherKey = Fixture.Hex(pub.PublicKeySpki) };
        Assert.Throws<XMeshException>(() => m.Validate());
    }

    [Fact]
    public void Inconsistent_chunk_count_is_rejected()
    {
        using var pub = NodeIdentity.Generate();
        var m = new AssetManifest { AssetId = "a", Version = "1", Size = 10_000, ChunkSize = 4096,
            Chunks = new() { new string('a', 64) }, Publisher = "p", PublisherKey = Fixture.Hex(pub.PublicKeySpki) };
        Assert.Throws<XMeshException>(() => m.Validate());
    }

    [Fact]
    public void Json_roundtrip_preserves_signature_validity()
    {
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(Fixture.RandomBytes(20_000), pub);
        var back = AssetManifest.FromJson(m.ToJson());
        Assert.True(ManifestSigner.VerifySignature(back));
        Assert.Equal(m.ComputeRoot(), back.ComputeRoot());
    }

    [Fact]
    public void Unknown_json_fields_are_rejected()
    {
        Assert.Throws<XMeshException>(() => AssetManifest.FromJson("{\"format\":1,\"bogus\":true}"));
    }

    [Fact]
    public void Zero_byte_asset_is_valid()
    {
        using var pub = NodeIdentity.Generate();
        var m = Fixture.Manifest(Array.Empty<byte>(), pub);
        Assert.Equal(0, m.ChunkCount);
        Assert.True(ManifestSigner.VerifySignature(m));
    }

    [Fact]
    public void Identity_persists_across_loads()
    {
        using var t = new TempDir();
        var p = Path.Combine(t.Path, "id.key");
        using var a = NodeIdentity.LoadOrCreate(p);
        using var b = NodeIdentity.LoadOrCreate(p);
        Assert.Equal(a.Id, b.Id);
    }
}
