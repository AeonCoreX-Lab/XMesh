using XMesh.Core;
using XMesh.Security;
using Xunit;

namespace XMesh.Tests;

public class HandshakeTests
{
    [Fact]
    public void Valid_proof_verifies()
    {
        using var a = NodeIdentity.Generate(); using var b = NodeIdentity.Generate();
        var na = Handshake.NewNonce(); var nb = Handshake.NewNonce();
        var proofA = Handshake.Prove(a, Handshake.Role.Initiator, na, nb, b.PublicKeySpki);
        Assert.True(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Initiator, na, nb, b.PublicKeySpki, proofA));
    }

    [Fact]
    public void Proof_cannot_be_replayed_in_a_different_session()
    {
        using var a = NodeIdentity.Generate(); using var b = NodeIdentity.Generate();
        var na = Handshake.NewNonce(); var nb = Handshake.NewNonce();
        var proof = Handshake.Prove(a, Handshake.Role.Initiator, na, nb, b.PublicKeySpki);
        var nb2 = Handshake.NewNonce(); // attacker replays into a fresh session with a new responder nonce
        Assert.False(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Initiator, na, nb2, b.PublicKeySpki, proof));
    }

    [Fact]
    public void Proof_cannot_be_reflected_back_as_the_other_role()
    {
        using var a = NodeIdentity.Generate(); using var b = NodeIdentity.Generate();
        var na = Handshake.NewNonce(); var nb = Handshake.NewNonce();
        var proofAsInitiator = Handshake.Prove(a, Handshake.Role.Initiator, na, nb, b.PublicKeySpki);
        // Reflection: attacker presents the initiator's proof claiming to be the responder.
        Assert.False(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Responder, na, nb, b.PublicKeySpki, proofAsInitiator));
    }

    [Fact]
    public void Proof_is_bound_to_the_intended_peer()
    {
        using var a = NodeIdentity.Generate(); using var b = NodeIdentity.Generate(); using var c = NodeIdentity.Generate();
        var na = Handshake.NewNonce(); var nb = Handshake.NewNonce();
        var proof = Handshake.Prove(a, Handshake.Role.Initiator, na, nb, b.PublicKeySpki);
        // A meant to talk to B; C must not be able to accept it.
        Assert.False(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Initiator, na, nb, c.PublicKeySpki, proof));
    }

    [Fact]
    public void Attacker_without_the_private_key_cannot_forge_a_proof()
    {
        using var victim = NodeIdentity.Generate(); using var attacker = NodeIdentity.Generate(); using var b = NodeIdentity.Generate();
        var na = Handshake.NewNonce(); var nb = Handshake.NewNonce();
        // Attacker claims victim's public key but signs with their own key.
        var forged = Handshake.Prove(attacker, Handshake.Role.Initiator, na, nb, b.PublicKeySpki);
        Assert.False(Handshake.VerifyPeer(victim.PublicKeySpki, Handshake.Role.Initiator, na, nb, b.PublicKeySpki, forged));
    }

    [Fact]
    public void Garbage_signature_returns_false_and_does_not_throw()
    {
        using var a = NodeIdentity.Generate(); using var b = NodeIdentity.Generate();
        var n = Handshake.NewNonce();
        Assert.False(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Initiator, n, n, b.PublicKeySpki, new byte[64]));
        Assert.False(Handshake.VerifyPeer(a.PublicKeySpki, Handshake.Role.Initiator, n, n, b.PublicKeySpki, new byte[3]));
        Assert.False(Handshake.VerifyPeer(new byte[10], Handshake.Role.Initiator, n, n, b.PublicKeySpki, new byte[64]));
    }

    [Fact]
    public void Nonces_are_unique()
    {
        var set = new HashSet<string>(Enumerable.Range(0, 500).Select(_ => Convert.ToHexString(Handshake.NewNonce())));
        Assert.Equal(500, set.Count);
    }

    [Fact]
    public void Allowlist_gate_enforces_authorization_separately_from_authentication()
    {
        using var a = NodeIdentity.Generate();
        var trust = new MemoryTrustStore();
        var ex = Assert.Throws<XMeshException>(() => Handshake.RequireAllowed(trust, a.Id, requireAllowlist: true));
        Assert.Equal(XMeshErrorCode.PeerRejected, ex.Code);
        Handshake.RequireAllowed(trust, a.Id, requireAllowlist: false); // policy off => permitted
        trust.AllowPeer(a.Id);
        Handshake.RequireAllowed(trust, a.Id, requireAllowlist: true);
    }

    [Fact]
    public void NodeId_is_derived_from_public_key_not_address()
    {
        using var a = NodeIdentity.Generate();
        Assert.Equal(NodeId.FromPublicKey(a.PublicKeySpki), a.Id);
        Assert.Equal(64, a.Id.ToHex().Length);
    }
}
