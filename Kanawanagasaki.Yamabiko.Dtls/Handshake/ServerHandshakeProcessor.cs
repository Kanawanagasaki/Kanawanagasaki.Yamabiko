namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using Org.BouncyCastle.Tls;
using System;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class ServerHandshakeProcessor : IDisposable
{
    private const string HKDF_PREFIX = "dtls13";
    private static readonly byte[] CERT_VERIFY_PREFIX = [0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x54, 0x4C, 0x53, 0x20, 0x31, 0x2E, 0x33, 0x2C, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00];

    public byte[]? ServerApplicationKey { get; private set; }
    public byte[]? ServerApplicationIV { get; private set; }
    public byte[]? ClientApplicationKey { get; private set; }
    public byte[]? ClientApplicationIV { get; private set; }
    public byte[]? ServerRecordNumberKey { get; private set; }
    public byte[]? ClientRecordNumberKey { get; private set; }

    private Dictionary<ushort, HandshakeMessage> _clientSeqNumToMessage = new();
    private Dictionary<ushort, HandshakeMessage> _serverSeqNumToMessage = new();

    private X509Certificate2 _certificate;

    private int _mtu;

    private AesGcm? _serverHandshakeAes;
    private byte[]? _serverHandshakeIV;
    private Aes? _serverRecordNumberAes;

    private AesGcm? _clientHandshakeAes;
    private byte[]? _clientHandshakeIV;
    private Aes? _clientRecordNumberAes;

    private HandshakeMessage? _clientHelloMessage;
    private byte[]? _clientHelloMessageHash;
    private List<byte[]> _cachedHandshaked = new();

    private byte[]? _clientSecret;
    private byte[]? _handshakeSecret;

    public ServerHandshakeProcessor(X509Certificate2 certificate, int mtu)
    {
        if (!certificate.HasPrivateKey)
            throw new ArgumentException("The provided certificate must include a private key", nameof(certificate));

        _certificate = certificate;
        _mtu = mtu;
    }

    public IEnumerable<byte[]> ProcessPacket(ReadOnlyMemory<byte> buffer)
    {
        if (buffer.Length <= 0)
            yield break;

        int offset = 0;

        while (offset < buffer.Length)
        {
            if ((buffer.Span[offset] & (byte)EHeaderFlags.FIXED_BITS) == CipherTextRecord.HEADER_BITS)
            {
                if (_clientHandshakeAes is null || _clientRecordNumberAes is null)
                    continue;

                var record = CipherTextRecord.DecryptAndParse(buffer.Span, _clientHandshakeAes, _clientHandshakeIV, _clientRecordNumberAes, ref offset);
                if (record.Type is not ERecordType.HANDSHAKE)
                    continue;

                var handshakeFragment = HandshakeFragment.Parse(record.Buffer);
                foreach (var packet in ProcessFragment(handshakeFragment))
                    yield return packet;
            }
            else
            {
                var record = PlainTextRecord.Parse(buffer.Span, ref offset);
                if (record.Type is not ERecordType.HANDSHAKE)
                    continue;

                var handshakeFragment = HandshakeFragment.Parse(record.Buffer);
                foreach (var packet in ProcessFragment(handshakeFragment))
                    yield return packet;
            }
        }
    }

    private IEnumerable<byte[]> ProcessFragment(HandshakeFragment fragment)
    {
        if (1 < fragment.SequenceNumber)
            yield break;

        if (!_clientSeqNumToMessage.TryGetValue(fragment.SequenceNumber, out var message))
            _clientSeqNumToMessage[fragment.SequenceNumber] = message = new HandshakeMessage(fragment);

        if (message.Handshake is null)
            message.AddFragment(fragment);

        if (message.Handshake is null)
            yield break;

        switch (message.Handshake)
        {
            case ClientHelloHandshake clientHello:
                {
                    _clientHelloMessage = message;

                    var clientHelloMessageHash = KeyHashHelper.HashFragments([_clientHelloMessage.GetFragment()]);
                    if (_clientHelloMessageHash is not null
                        && CryptographicOperations.FixedTimeEquals(clientHelloMessageHash, _clientHelloMessageHash)
                        && 0 < _cachedHandshaked.Count)
                    {
                        foreach (var packet in _cachedHandshaked)
                            yield return packet;
                    }
                    else
                    {
                        _cachedHandshaked.Clear();
                        foreach (var packet in ProcessClientHello(clientHello))
                        {
                            _cachedHandshaked.Add(packet);
                            yield return packet;
                        }

                        _clientHelloMessageHash = clientHelloMessageHash;
                    }

                    break;
                }
            case FinishedHandshake clientFinished:
                {
                    var packet = ProcessClientFinished(clientFinished);
                    if (packet is not null)
                        yield return packet;
                    break;
                }
        }
    }

    private IEnumerable<byte[]> ProcessClientHello(ClientHelloHandshake clientHello)
    {
        if (_clientHelloMessage is null)
            yield break;

        if (!clientHello.CipherSuites.Contains(ECipherSuite.TLS_AES_128_GCM_SHA256))
            yield break;

        KeyShareExtension? keyShare = null;
        SupportedVersionsExtension? supportedVersions = null;
        SignatureAlgorithmsExtension? signatureAlgorithms = null;
        EncryptThenMacExtension? encryptThenMac = null;
        SupportedGroupsExtension? supportedGroups = null;

        foreach (var extension in clientHello.Extensions)
        {
            if (extension is KeyShareExtension)
                keyShare = (KeyShareExtension)extension;
            if (extension is SupportedVersionsExtension)
                supportedVersions = (SupportedVersionsExtension)extension;
            if (extension is SignatureAlgorithmsExtension)
                signatureAlgorithms = (SignatureAlgorithmsExtension)extension;
            if (extension is EncryptThenMacExtension)
                encryptThenMac = (EncryptThenMacExtension)extension;
            if (extension is SupportedGroupsExtension)
                supportedGroups = (SupportedGroupsExtension)extension;
        }

        if (keyShare is null)
            yield break;
        if (!keyShare.GroupToKey.ContainsKey(ENamedGroup.X25519))
            yield break;

        var clientPublicKey = keyShare.GroupToKey[ENamedGroup.X25519];
        if (clientPublicKey.Length != 32)
            yield break;

        if (supportedVersions is null)
            yield break;
        if (!supportedVersions.Versions.Contains(EVersions.DTLS1_3))
            yield break;

        if (signatureAlgorithms is null)
            yield break;
        if (!signatureAlgorithms.Algorithms.Contains(ESignatureAlgorithm.RSA_PSS_RSAE_SHA256))
            yield break;

        if (encryptThenMac is null)
            yield break;

        if (supportedGroups is null)
            yield break;
        if (!supportedGroups.Groups.Contains(ENamedGroup.X25519))
            yield break;

        var privateKey = RandomNumberGenerator.GetBytes(32);
        var publicKey = KeyHashHelper.GenerateX25519PublicKey(privateKey);
        var random = RandomNumberGenerator.GetBytes(32);

        var serverHello = new ServerHelloHandshake(random, ECipherSuite.TLS_AES_128_GCM_SHA256,
            [
                new SupportedVersionsExtension([EVersions.DTLS1_3]),
                new KeyShareExtension(new() { [ENamedGroup.X25519] = publicKey })
            ]
        );
        var serverHelloMessage = new HandshakeMessage(serverHello, 0);
        foreach (var buffer in SerializePlainText(serverHelloMessage))
            yield return buffer;

        var helloHash = KeyHashHelper.HashFragments([_clientHelloMessage.GetFragment(), serverHelloMessage.GetFragment()]);
        var sharedSecret = KeyHashHelper.SharedSecret(privateKey, clientPublicKey);

        var zeros = new byte[32];
        var earlySecret = KeyHashHelper.HKDF_Extract(zeros, zeros);
        var emptyHash = SHA256.HashData(Array.Empty<byte>());
        var derived = KeyHashHelper.HKDF_ExpandLabel(earlySecret, "derived", emptyHash, helloHash.Length, HKDF_PREFIX);

        _handshakeSecret = KeyHashHelper.HKDF_Extract(derived, sharedSecret);
        _clientSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "c hs traffic", helloHash, HKDF_PREFIX);
        var serverSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "s hs traffic", helloHash, HKDF_PREFIX);

        var clientHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "key", Array.Empty<byte>(), 16, HKDF_PREFIX);
        var serverHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "key", Array.Empty<byte>(), 16, HKDF_PREFIX);
        var clientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "sn", Array.Empty<byte>(), 16, HKDF_PREFIX);
        var serverRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "sn", Array.Empty<byte>(), 16, HKDF_PREFIX);

        _clientHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "iv", Array.Empty<byte>(), 12, HKDF_PREFIX);
        _serverHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "iv", Array.Empty<byte>(), 12, HKDF_PREFIX);

        _serverHandshakeAes?.Dispose();
        _serverRecordNumberAes?.Dispose();
        _clientHandshakeAes?.Dispose();
        _clientRecordNumberAes?.Dispose();

        _serverHandshakeAes = new AesGcm(serverHandshakeKey, AesGcm.TagByteSizes.MaxSize);
        _clientHandshakeAes = new AesGcm(clientHandshakeKey, AesGcm.TagByteSizes.MaxSize);

        _serverRecordNumberAes = Aes.Create();
        _serverRecordNumberAes.KeySize = 128;
        _serverRecordNumberAes.Key = serverRecordNumberKey;
        _serverRecordNumberAes.Mode = CipherMode.ECB;
        _serverRecordNumberAes.Padding = PaddingMode.None;

        _clientRecordNumberAes = Aes.Create();
        _clientRecordNumberAes.KeySize = 128;
        _clientRecordNumberAes.Key = clientRecordNumberKey;
        _clientRecordNumberAes.Mode = CipherMode.ECB;
        _clientRecordNumberAes.Padding = PaddingMode.None;

        var encryptedExtensions = new EncryptedExtensionsHandshake([new SupportedGroupsExtension([ENamedGroup.X25519])]);
        var encryptedExtensionsMessage = new HandshakeMessage(encryptedExtensions, 1);
        foreach (var buffer in SerializeCipherText(encryptedExtensionsMessage, 2, 0))
            yield return buffer;

        var serverCertificate = new ServerCertificateHandshake([new CertificateBuffer(_certificate)]);
        var serverCertificateMessage = new HandshakeMessage(serverCertificate, 2);
        foreach (var buffer in SerializeCipherText(serverCertificateMessage, 2, 1))
            yield return buffer;

        var certVerifyHash = KeyHashHelper.HashFragments(
            [
                _clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment()
            ]
        );

        var certVerifyLength = CERT_VERIFY_PREFIX.Length + certVerifyHash.Length;
        var toSign = new byte[certVerifyLength];
        CERT_VERIFY_PREFIX.CopyTo(toSign.AsSpan(0, CERT_VERIFY_PREFIX.Length));
        certVerifyHash.CopyTo(toSign.AsSpan(CERT_VERIFY_PREFIX.Length, certVerifyHash.Length));

        using var rsa = _certificate.GetRSAPrivateKey();
        if (rsa is null)
            throw new InvalidOperationException("The server certificate does not contain an RSA private key");

        var signature = rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var serverCertVerify = new ServerCertVerifyHandshake(ESignatureAlgorithm.RSA_PSS_RSAE_SHA256, signature);
        var serverCertVerifyMessage = new HandshakeMessage(serverCertVerify, 3);
        foreach (var buffer in SerializeCipherText(serverCertVerifyMessage, 2, 2))
            yield return buffer;

        var finishedKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "finished", Array.Empty<byte>(), 32, HKDF_PREFIX);
        var finishedHash = KeyHashHelper.HashFragments(
            [
                _clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment(),
                serverCertVerifyMessage.GetFragment()
            ]
        );
        var verifyData = HMACSHA256.HashData(finishedKey, finishedHash);

        var serverFinished = new FinishedHandshake(verifyData);
        var serverFinishedMessage = new HandshakeMessage(serverFinished, 4);
        foreach (var buffer in SerializeCipherText(serverFinishedMessage, 2, 3))
            yield return buffer;
    }

    private byte[]? ProcessClientFinished(FinishedHandshake clientFinished)
    {
        if (_clientSecret is null)
            return null;
        if (_handshakeSecret is null)
            return null;

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            return null;
        if (clientHelloMessage.Handshake is not ClientHelloHandshake)
            return null;

        if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
            return null;
        if (serverHelloMessage.Handshake is not ServerHelloHandshake)
            return null;

        if (!_serverSeqNumToMessage.TryGetValue(1, out var encryptedExtensionsMessage))
            return null;
        if (encryptedExtensionsMessage.Handshake is not EncryptedExtensionsHandshake)
            return null;

        if (!_serverSeqNumToMessage.TryGetValue(2, out var serverCertificateMessage))
            return null;
        if (serverCertificateMessage.Handshake is not ServerCertificateHandshake)
            return null;

        if (!_serverSeqNumToMessage.TryGetValue(3, out var serverCertVerifyMessage))
            return null;
        if (serverCertVerifyMessage.Handshake is not ServerCertVerifyHandshake)
            return null;

        if (!_serverSeqNumToMessage.TryGetValue(4, out var serverFinishedMessage))
            return null;
        if (serverFinishedMessage.Handshake is not FinishedHandshake)
            return null;

        var finishedKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "finished", Array.Empty<byte>(), 32, HKDF_PREFIX);
        var hash = KeyHashHelper.HashFragments(
            [
                clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment(),
                serverCertVerifyMessage.GetFragment(),
                serverFinishedMessage.GetFragment()
            ]
        );

        var verifyData = HMACSHA256.HashData(finishedKey, hash);

        if (!CryptographicOperations.FixedTimeEquals(clientFinished.VerifyData, verifyData))
            return null;

        var zeros = new byte[32];
        var derivedSecret = KeyHashHelper.HKDF_ExpandLabel(_handshakeSecret, "derived", Array.Empty<byte>(), 32, HKDF_PREFIX);
        var masterSecret = KeyHashHelper.HKDF_Extract(derivedSecret, zeros);
        var clientSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "c ap traffic", hash, 32, HKDF_PREFIX);
        var serverSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "s ap traffic", hash, 32, HKDF_PREFIX);

        ClientApplicationKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "key", Array.Empty<byte>(), 16, HKDF_PREFIX);
        ServerApplicationKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "key", Array.Empty<byte>(), 16, HKDF_PREFIX);
        ClientApplicationIV = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "iv", Array.Empty<byte>(), 12, HKDF_PREFIX);
        ServerApplicationIV = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "iv", Array.Empty<byte>(), 12, HKDF_PREFIX);
        ClientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "sn", Array.Empty<byte>(), 16, HKDF_PREFIX);
        ServerRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "sn", Array.Empty<byte>(), 16, HKDF_PREFIX);

        var ack = new Ack(2, 0);
        var ackBuffer = new byte[ack.Length()];
        ack.Write(ackBuffer);
        var record = new CipherTextRecord(ackBuffer)
        {
            Type = ERecordType.ACK,
            EpochLowBits = 3,
            RecordNumber = 0
        };

        using var ackAes = new AesGcm(ServerApplicationKey, AesGcm.TagByteSizes.MaxSize);

        using var ackHeaderAes = Aes.Create();
        ackHeaderAes.KeySize = 128;
        ackHeaderAes.Key = ServerRecordNumberKey;
        ackHeaderAes.Mode = CipherMode.ECB;
        ackHeaderAes.Padding = PaddingMode.None;

        var recordBuffer = new byte[record.Length()];
        record.EncryptAndWrite(recordBuffer, ackAes, ServerApplicationIV, ackHeaderAes);

        return recordBuffer;
    }

    private IEnumerable<byte[]> SerializePlainText(HandshakeMessage message)
    {
        _serverSeqNumToMessage[message.SequenceNumber] = message;

        var fragments = message.GetFragments(Math.Max(39, _mtu - 25));
        foreach (var fragment in fragments)
        {
            var fragmentBuffer = new byte[fragment.Length()];
            fragment.Write(fragmentBuffer);

            var record = new PlainTextRecord(fragmentBuffer)
            {
                Type = ERecordType.HANDSHAKE,
                KeyEpoch = 0,
                RecordNumber = 0
            };

            var recordBuffer = new byte[record.Length()];
            record.Write(recordBuffer);

            yield return recordBuffer;
        }
    }

    private IEnumerable<byte[]> SerializeCipherText(HandshakeMessage message, byte epoch, ushort recordNumber)
    {
        if (_serverHandshakeAes is null)
            yield break;
        if (_serverHandshakeIV is null)
            yield break;
        if (_serverRecordNumberAes is null)
            yield break;

        _serverSeqNumToMessage[message.SequenceNumber] = message;

        var fragments = message.GetFragments(Math.Max(30, _mtu - 34));
        foreach (var fragment in fragments)
        {
            var fragmentBuffer = new byte[fragment.Length()];
            fragment.Write(fragmentBuffer);

            var record = new CipherTextRecord(fragmentBuffer)
            {
                Type = ERecordType.HANDSHAKE,
                EpochLowBits = epoch,
                RecordNumber = recordNumber
            };

            var recordBuffer = new byte[record.Length()];
            record.EncryptAndWrite(recordBuffer, _serverHandshakeAes, _serverHandshakeIV, _serverRecordNumberAes);

            yield return recordBuffer;
        }
    }

    public void Dispose()
    {
        _serverHandshakeAes?.Dispose();
        _serverHandshakeAes = null;
        _serverRecordNumberAes?.Dispose();
        _serverRecordNumberAes = null;
        _clientHandshakeAes?.Dispose();
        _clientHandshakeAes = null;
        _clientRecordNumberAes?.Dispose();
        _clientRecordNumberAes = null;
    }
}
