namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class ServerHandshakeProcessor : IDisposable
{
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
        {
            yield return GetAlertPlainText(EAlertType.DECODE_ERROR);
            yield break;
        }

        int offset = 0;

        while (offset < buffer.Length)
        {
            if ((buffer.Span[offset] & (byte)EHeaderFlags.FIXED_BITS) == CipherTextRecord.HEADER_BITS)
            {
                if (_clientHandshakeAes is null || _clientRecordNumberAes is null)
                    break;

                var record = CipherTextRecord.DecryptAndParse(buffer.Span, _clientHandshakeAes, _clientHandshakeIV, _clientRecordNumberAes, 0, 0, ref offset);
                if (record.Type is not ERecordType.HANDSHAKE)
                    continue;

                var handshakeFragment = HandshakeFragment.Parse(record.Buffer);
                foreach (var packet in ProcessFragment(handshakeFragment))
                    yield return packet;
            }
            else
            {
                var record = PlainTextRecord.Parse(buffer.Span, 0, 0, ref offset);
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
        {
            yield return GetAlertPlainText(EAlertType.DECODE_ERROR);
            yield break;
        }

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
            default:
                yield return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
                break;
        }
    }

    private IEnumerable<byte[]> ProcessClientHello(ClientHelloHandshake clientHello)
    {
        if (_clientHelloMessage is null)
            yield break;

        if (!clientHello.CipherSuites.Contains(ECipherSuite.TLS_AES_128_GCM_SHA256))
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

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
        {
            yield return GetAlertPlainText(EAlertType.MISSING_EXTENSION);
            yield break;
        }
        if (!keyShare.GroupToKey.ContainsKey(ENamedGroup.X25519))
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

        var clientPublicKey = keyShare.GroupToKey[ENamedGroup.X25519];
        if (clientPublicKey.Length != 32)
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

        if (supportedVersions is null)
        {
            yield return GetAlertPlainText(EAlertType.MISSING_EXTENSION);
            yield break;
        }
        if (!supportedVersions.Versions.Contains(EVersions.DTLS1_3))
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

        if (signatureAlgorithms is null)
        {
            yield return GetAlertPlainText(EAlertType.MISSING_EXTENSION);
            yield break;
        }
        if (!signatureAlgorithms.Algorithms.Contains(ESignatureAlgorithm.RSA_PSS_RSAE_SHA256))
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

        if (encryptThenMac is null)
        {
            yield return GetAlertPlainText(EAlertType.MISSING_EXTENSION);
            yield break;
        }

        if (supportedGroups is null)
        {
            yield return GetAlertPlainText(EAlertType.MISSING_EXTENSION);
            yield break;
        }
        if (!supportedGroups.Groups.Contains(ENamedGroup.X25519))
        {
            yield return GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
            yield break;
        }

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
        var derived = KeyHashHelper.HKDF_ExpandLabel(earlySecret, "derived", emptyHash, helloHash.Length, KeyHashHelper.DTLS_PREFIX);

        _handshakeSecret = KeyHashHelper.HKDF_Extract(derived, sharedSecret);
        _clientSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "c hs traffic", helloHash, KeyHashHelper.DTLS_PREFIX);
        var serverSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "s hs traffic", helloHash, KeyHashHelper.DTLS_PREFIX);

        var clientHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        var serverHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        var clientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        var serverRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);

        _clientHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        _serverHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);

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

        var certVerifyLength = KeyHashHelper.CERT_VERIFY_PREFIX.Length + certVerifyHash.Length;
        var toSign = new byte[certVerifyLength];
        KeyHashHelper.CERT_VERIFY_PREFIX.CopyTo(toSign.AsSpan(0, KeyHashHelper.CERT_VERIFY_PREFIX.Length));
        certVerifyHash.CopyTo(toSign.AsSpan(KeyHashHelper.CERT_VERIFY_PREFIX.Length, certVerifyHash.Length));

        using var rsa = _certificate.GetRSAPrivateKey();
        if (rsa is null)
        {
            yield return GetAlertPlainText(EAlertType.INTERNAL_ERROR);
            throw new InvalidOperationException("The server certificate does not contain an RSA private key");
        }

        var signature = rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var serverCertVerify = new ServerCertVerifyHandshake(ESignatureAlgorithm.RSA_PSS_RSAE_SHA256, signature);
        var serverCertVerifyMessage = new HandshakeMessage(serverCertVerify, 3);
        foreach (var buffer in SerializeCipherText(serverCertVerifyMessage, 2, 2))
            yield return buffer;

        var finishedKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "finished", Array.Empty<byte>(), 32, KeyHashHelper.DTLS_PREFIX);
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

        ClientApplicationKey = null;
        ServerApplicationKey = null;
        ClientApplicationIV = null;
        ServerApplicationIV = null;
        ClientRecordNumberKey = null;
        ServerRecordNumberKey = null;
    }

    private byte[] ProcessClientFinished(FinishedHandshake clientFinished)
    {
        if (_clientSecret is null)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);
        if (_handshakeSecret is null)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (clientHelloMessage.Handshake is not ClientHelloHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (serverHelloMessage.Handshake is not ServerHelloHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_serverSeqNumToMessage.TryGetValue(1, out var encryptedExtensionsMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (encryptedExtensionsMessage.Handshake is not EncryptedExtensionsHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_serverSeqNumToMessage.TryGetValue(2, out var serverCertificateMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (serverCertificateMessage.Handshake is not ServerCertificateHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_serverSeqNumToMessage.TryGetValue(3, out var serverCertVerifyMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (serverCertVerifyMessage.Handshake is not ServerCertVerifyHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        if (!_serverSeqNumToMessage.TryGetValue(4, out var serverFinishedMessage))
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);
        if (serverFinishedMessage.Handshake is not FinishedHandshake)
            return GetAlertCipherText(EAlertType.INTERNAL_ERROR) ?? GetAlertPlainText(EAlertType.INTERNAL_ERROR);

        var finishedKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "finished", Array.Empty<byte>(), 32, KeyHashHelper.DTLS_PREFIX);
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
            return GetAlertCipherText(EAlertType.HANDSHAKE_FAILURE) ?? GetAlertPlainText(EAlertType.HANDSHAKE_FAILURE);

        var zeros = new byte[32];
        var derivedSecret = KeyHashHelper.HKDF_ExpandLabel(_handshakeSecret, "derived", Array.Empty<byte>(), 32, KeyHashHelper.DTLS_PREFIX);
        var masterSecret = KeyHashHelper.HKDF_Extract(derivedSecret, zeros);
        var clientSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "c ap traffic", hash, 32, KeyHashHelper.DTLS_PREFIX);
        var serverSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "s ap traffic", hash, 32, KeyHashHelper.DTLS_PREFIX);

        ClientApplicationKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ServerApplicationKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ClientApplicationIV = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        ServerApplicationIV = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        ClientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ServerRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);

        var ack = new Ack(2, 0);
        var ackBuffer = new byte[ack.Length()];
        ack.Write(ackBuffer);
        var record = new CipherTextRecord(ackBuffer)
        {
            Type = ERecordType.ACK,
            Epoch = 3,
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

    public byte[] GetAlertPlainText(EAlertType type)
    {
        var alert = new Alert(type);
        var alertBuffer = new byte[alert.Length()];
        alert.Write(alertBuffer);

        var record = new PlainTextRecord(alertBuffer)
        {
            Type = ERecordType.ALERT,
            Epoch = 0,
            RecordNumber = 0
        };
        var recordBuffer = new byte[record.Length()];
        record.Write(recordBuffer);

        return recordBuffer;
    }

    public byte[]? GetAlertCipherText(EAlertType type)
    {
        if (_serverHandshakeAes is null)
            return null;
        if (_serverHandshakeIV is null)
            return null;
        if (_serverRecordNumberAes is null)
            return null;

        var alert = new Alert(type);
        var alertBuffer = new byte[alert.Length()];
        alert.Write(alertBuffer);

        var record = new CipherTextRecord(alertBuffer)
        {
            Type = ERecordType.ALERT,
            Epoch = 2,
            RecordNumber = (ulong)_serverSeqNumToMessage.Count
        };
        var recordBuffer = new byte[record.Length()];
        record.EncryptAndWrite(recordBuffer, _serverHandshakeAes, _serverHandshakeIV, _serverRecordNumberAes);

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
                Epoch = 0,
                RecordNumber = 0
            };

            var recordBuffer = new byte[record.Length()];
            record.Write(recordBuffer);

            yield return recordBuffer;
        }
    }

    private IEnumerable<byte[]> SerializeCipherText(HandshakeMessage message, ulong epoch, ulong recordNumber)
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
                Epoch = epoch,
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
