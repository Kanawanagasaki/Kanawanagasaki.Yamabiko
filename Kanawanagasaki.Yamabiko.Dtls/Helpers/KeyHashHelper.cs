namespace Kanawanagasaki.Yamabiko.Dtls.Helpers;

using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class KeyHashHelper
{
    public static byte[] GenerateX25519PublicKey(ReadOnlySpan<byte> privateKey)
    {
        var privParam = new X25519PrivateKeyParameters(privateKey);
        var pubParam = privParam.GeneratePublicKey();
        return pubParam.GetEncoded();
    }

    public static byte[] HashFragments(HandshakeFragment[] fragments)
    {
        if (fragments.Any(x => x.FragmentOffset != 0 || x.FragmentLength != x.TotalLength))
            throw new ArgumentException("One or many fragments was truncated", nameof(fragments));

        var length = 4 * fragments.Length + fragments.Sum(x => x.Fragment.Length);
        Span<byte> buffer = length < 1024 ? stackalloc byte[length] : new byte[length];

        int offset = 0;

        foreach (var fragment in fragments)
        {
            buffer[offset++] = (byte)fragment.Type;
            buffer[offset++] = (byte)((fragment.Fragment.Length >> 16) & 0xFF);
            buffer[offset++] = (byte)((fragment.Fragment.Length >> 8) & 0xFF);
            buffer[offset++] = (byte)(fragment.Fragment.Length & 0xFF);
            fragment.Fragment.CopyTo(buffer.Slice(offset, fragment.Fragment.Length));
            offset += fragment.Fragment.Length;
        }

        return SHA256.HashData(buffer);
    }

    public static byte[] SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
    {
        var clientPrivParam = new X25519PrivateKeyParameters(privateKey);
        var serverPubParam = new X25519PublicKeyParameters(publicKey);
        var buffer = new byte[32];
        clientPrivParam.GenerateSecret(serverPubParam, buffer, 0);
        return buffer;
    }

    public static byte[] HKDF_Extract(byte[] salt, byte[] ikm)
    {
        var h = new HMac(new Sha256Digest());
        if (salt == null || salt.Length == 0)
            salt = new byte[32];
        h.Init(new KeyParameter(salt));
        h.BlockUpdate(ikm, 0, ikm.Length);
        var prk = new byte[h.GetMacSize()];
        h.DoFinal(prk, 0);
        return prk;
    }

    public static byte[] HKDF_Expand(byte[] prk, byte[] info, int L)
    {
        var h = new HMac(new Sha256Digest());
        int hashOut = h.GetMacSize();
        int n = (L + hashOut - 1) / hashOut;
        var okm = new byte[L];
        var t = new byte[0];
        int pos = 0;
        for (int i = 1; i <= n; i++)
        {
            h.Init(new KeyParameter(prk));
            if (t.Length > 0)
                h.BlockUpdate(t, 0, t.Length);
            if (info != null && info.Length > 0)
                h.BlockUpdate(info, 0, info.Length);
            h.Update((byte)i);
            var outBlock = new byte[hashOut];
            h.DoFinal(outBlock, 0);
            int copy = Math.Min(hashOut, L - pos);
            Array.Copy(outBlock, 0, okm, pos, copy);
            pos += copy;
            t = outBlock;
        }
        return okm;
    }

    public static byte[] HKDF_ExpandLabel(byte[] secret, string label, byte[] context, int length, string prefix)
    {
        var labelBytes = Encoding.ASCII.GetBytes(prefix + label);
        if (context == null)
            context = Array.Empty<byte>();

        var lengthBytes = new byte[2] { (byte)((length >> 8) & 0xff), (byte)(length & 0xff) };
        if (labelBytes.Length > 255 || context.Length > 255)
            throw new ArgumentException("label/context too long");

        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        int offset = 0;
        Array.Copy(lengthBytes, 0, info, offset, 2);
        offset += 2;
        info[offset++] = (byte)labelBytes.Length;
        Array.Copy(labelBytes, 0, info, offset, labelBytes.Length);
        offset += labelBytes.Length;
        info[offset++] = (byte)context.Length;
        if (context.Length > 0)
            Array.Copy(context, 0, info, offset, context.Length);

        return HKDF_Expand(secret, info, length);
    }

    public static byte[] DeriveSecret(byte[] secret, string label, byte[] transcriptHash, string prefix)
    {
        return HKDF_ExpandLabel(secret, label, transcriptHash, 32, prefix);
    }
}
