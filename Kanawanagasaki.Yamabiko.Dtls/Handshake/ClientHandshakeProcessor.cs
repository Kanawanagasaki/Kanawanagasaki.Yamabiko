namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public abstract class ClientHandshakeProcessor : IDisposable
{
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(90);
    public TimeSpan ResendInterval { get; set; } = TimeSpan.FromSeconds(3);

    public EClientHandshakeState State { get; private set; } = EClientHandshakeState.NONE;

    public byte[]? ServerApplicationKey { get; private set; }
    public byte[]? ServerApplicationIV { get; private set; }
    public byte[]? ClientApplicationKey { get; private set; }
    public byte[]? ClientApplicationIV { get; private set; }
    public byte[]? ServerRecordNumberKey { get; private set; }
    public byte[]? ClientRecordNumberKey { get; private set; }

    private byte[]? _privateKey;
    private byte[]? _publicKey;
    private byte[]? _random;

    private Dictionary<ushort, HandshakeMessage> _clientSeqNumToMessage = new();
    private Dictionary<ushort, HandshakeMessage> _serverSeqNumToMessage = new();
    private Dictionary<EHandshakeType, HandshakeMessage> _handshakeTypeToMessage = new();

    private byte[]? _serverPublicKey;
    private byte[]? _helloHash;
    private byte[]? _sharedSecret;
    private byte[]? _handshakeSecret;
    private byte[]? _clientSecret;
    private byte[]? _serverSecret;
    private byte[]? _clientHandshakeKey;
    private byte[]? _clientHandshakeIV;
    private byte[]? _serverHandshakeKey;
    private byte[]? _serverHandshakeIV;
    private byte[]? _clientRecordNumberKey;
    private byte[]? _serverRecordNumberKey;

    private AesGcm? _serverHandshakeAes;
    private Aes? _serverRecordNumberAes;

    private AesGcm? _clientHandshakeAes;
    private Aes? _clientRecordNumberAes;

    private X509Certificate2? _serverCertificate;

    private ClientHelloHandshake? _clientHello;

    private void Reset(bool full)
    {
        if (full)
        {
            ServerApplicationKey = null;
            ServerApplicationIV = null;
            ClientApplicationKey = null;
            ClientApplicationIV = null;
            ServerRecordNumberKey = null;
            ClientRecordNumberKey = null;
        }

        if (_privateKey is not null)
            CryptographicOperations.ZeroMemory(_privateKey);
        _privateKey = null;
        _publicKey = null;
        _random = null;

        _clientSeqNumToMessage.Clear();
        _serverSeqNumToMessage.Clear();
        _handshakeTypeToMessage.Clear();

        _serverPublicKey = null;
        _helloHash = null;
        _sharedSecret = null;
        _handshakeSecret = null;
        _clientSecret = null;
        _serverSecret = null;
        _clientHandshakeKey = null;
        _clientHandshakeIV = null;
        _serverHandshakeKey = null;
        _serverHandshakeIV = null;
        _clientRecordNumberKey = null;
        _serverRecordNumberKey = null;

        _serverHandshakeAes?.Dispose();
        _serverHandshakeAes = null;
        _serverRecordNumberAes?.Dispose();
        _serverRecordNumberAes = null;
        _clientHandshakeAes?.Dispose();
        _clientHandshakeAes = null;
        _clientRecordNumberAes?.Dispose();
        _clientRecordNumberAes = null;

        _serverCertificate?.Dispose();
        _serverCertificate = null;

        _clientHello = null;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        if (State is not EClientHandshakeState.NONE
            && State is not EClientHandshakeState.FAILED
            && State is not EClientHandshakeState.DONE)
            throw new Exception("Handshake in progress");

        var startTime = Stopwatch.GetTimestamp();

        try
        {
            State = EClientHandshakeState.STARTED;

            Reset(true);

            _privateKey = RandomNumberGenerator.GetBytes(32);
            _publicKey = KeyHashHelper.GenerateX25519PublicKey(_privateKey);
            _random = RandomNumberGenerator.GetBytes(32);

            _clientHello = new ClientHelloHandshake(_random, [ECipherSuite.TLS_AES_128_GCM_SHA256],
                [
                    new KeyShareExtension(new() { [ENamedGroup.X25519] = _publicKey }),
                    new SupportedVersionsExtension([EVersions.DTLS1_3]),
                    new SignatureAlgorithmsExtension([ESignatureAlgorithm.ECDSA_SECP256R1_SHA256]),
                    new EncryptThenMacExtension(),
                    new SupportedGroupsExtension([ENamedGroup.X25519])
                ]
            );

            await SendClientHelloAsync(ct);

            State = EClientHandshakeState.WAITING_SERVER_HELLO;

            while (!ct.IsCancellationRequested && State is not EClientHandshakeState.DONE && State is not EClientHandshakeState.FAILED)
            {
                var timeoutWait = Timeout - Stopwatch.GetElapsedTime(startTime);
                if (timeoutWait < TimeSpan.Zero)
                    throw new TimeoutException();

                var minWait = ResendInterval;
                if (timeoutWait < minWait)
                    minWait = timeoutWait;

                using var intervalCts = new CancellationTokenSource();
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, intervalCts.Token);

                var receiveTask = ReceiveAsync(linkedCts.Token);
                var intervalTask = Task.Delay(minWait, linkedCts.Token);
                var firstTask = await Task.WhenAny(receiveTask, intervalTask);

                intervalCts.Cancel();

                if (firstTask == receiveTask)
                {
                    var buffer = await receiveTask;
                    if (0 < buffer.Length)
                        await ParsePacket(buffer, ct);
                    else
                        await ResendAsync(ct);
                }
                else
                    await ResendAsync(ct);
            }
        }
        catch
        {
            State = EClientHandshakeState.FAILED;
            throw;
        }
        finally
        {
            Reset(false);
        }
    }

    private async Task ParsePacket(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (buffer.Length <= 0)
            return;

        int offset = 0;

        while (offset < buffer.Length)
        {
            if ((buffer.Span[offset] & (byte)EHeaderFlags.FIXED_BITS) == CipherTextRecord.HEADER_BITS)
            {
                CipherTextRecord record;
                var epoch = buffer.Span[offset] & (byte)EHeaderFlags.ENCRYPTION_EPOCH;
                if (epoch == 2)
                {
                    if (_serverHandshakeAes is null || _serverRecordNumberAes is null)
                        return;

                    record = CipherTextRecord.DecryptAndParse(buffer.Span, _serverHandshakeAes, _serverHandshakeIV, _serverRecordNumberAes, 0, 0, ref offset);
                }
                else if (epoch == 3)
                {
                    if (ServerApplicationKey is null || ServerRecordNumberKey is null || ServerApplicationIV is null)
                        return;

                    using var ackAes = new AesGcm(ServerApplicationKey, AesGcm.TagByteSizes.MaxSize);

                    using var ackHeaderAes = Aes.Create();
                    ackHeaderAes.KeySize = 128;
                    ackHeaderAes.Key = ServerRecordNumberKey;
                    ackHeaderAes.Mode = CipherMode.ECB;
                    ackHeaderAes.Padding = PaddingMode.None;

                    record = CipherTextRecord.DecryptAndParse(buffer.Span, ackAes, ServerApplicationIV, ackHeaderAes, 0, 0, ref offset);
                }
                else return;

                if (record.Type is ERecordType.ACK)
                    ProcessServerAck();
                else if (record.Type is ERecordType.HANDSHAKE)
                {
                    var handshakeFragment = HandshakeFragment.Parse(record.Buffer.Span);
                    ParseFragment(handshakeFragment);
                    await TryProcessNextHandshakeMessage(ct);
                }
            }
            else
            {
                var record = PlainTextRecord.Parse(buffer.Span, 0, 0, ref offset);
                if(record.Type is ERecordType.ALERT)
                {
                    var alert = Alert.Parse(record.Buffer);
                    if (alert.Level == 2)
                        throw new IOException("Failed to finish handshake: " + alert.Type);
                }
                else if (record.Type is ERecordType.HANDSHAKE)
                {
                    var handshakeFragment = HandshakeFragment.Parse(record.Buffer);
                    ParseFragment(handshakeFragment);
                    await TryProcessNextHandshakeMessage(ct);
                }
            }
        }
    }

    private async Task TryProcessNextHandshakeMessage(CancellationToken ct)
    {
        if (State is EClientHandshakeState.WAITING_SERVER_HELLO
            && _handshakeTypeToMessage.TryGetValue(EHandshakeType.SERVER_HELLO, out var serverHelloMessage)
            && serverHelloMessage.Handshake is ServerHelloHandshake serverHello)
        {
            if (serverHelloMessage.SequenceNumber != 0)
                throw new FormatException("Server sent ServerHello out of order");
            ProcessServerHello(serverHello);
        }

        if (State is EClientHandshakeState.WAITING_ENCRYPTED_EXTENSIONS
            && _handshakeTypeToMessage.TryGetValue(EHandshakeType.ENCRYPTED_EXTENSIONS, out var encryptedExtensionsMessage)
            && encryptedExtensionsMessage.Handshake is EncryptedExtensionsHandshake encryptedExtensions)
        {
            if (encryptedExtensionsMessage.SequenceNumber != 1)
                throw new FormatException("Server sent Encrypted Extensions out of order");
            ProcessEncryptedExtensions(encryptedExtensions);
        }

        if (State is EClientHandshakeState.WAITING_CERTIFICATE
            && _handshakeTypeToMessage.TryGetValue(EHandshakeType.CERTIFICATE, out var serverCertificateMessage)
            && serverCertificateMessage.Handshake is ServerCertificateHandshake serverCertificate)
        {
            if (serverCertificateMessage.SequenceNumber != 2)
                throw new FormatException("Server sent certificate out of order");
            ProcessServerCertificate(serverCertificate);
        }

        if (State is EClientHandshakeState.WAITING_CERTIFICATE_VERIFY
            && _handshakeTypeToMessage.TryGetValue(EHandshakeType.CERTIFICATE_VERIFY, out var serverCertVerifyMessage)
            && serverCertVerifyMessage.Handshake is ServerCertVerifyHandshake serverCertVerify)
        {
            if (serverCertVerifyMessage.SequenceNumber != 3)
                throw new FormatException("Server sent certificate verify out of order");
            ProcessServerCertVerify(serverCertVerify);
        }

        if (State is EClientHandshakeState.WAITING_HANDSHAKE_FINISHED
            && _handshakeTypeToMessage.TryGetValue(EHandshakeType.FINISHED, out var serverFinishedMessage)
            && serverFinishedMessage.Handshake is FinishedHandshake serverFinished)
        {
            if (serverFinishedMessage.SequenceNumber != 4)
                throw new FormatException("Server sent finished out of order");
            await ProcessServerFinishedAsync(serverFinished, ct);
        }
    }

    private void ParseFragment(HandshakeFragment fragment)
    {
        if (4 < fragment.SequenceNumber)
            return;

        if (!_serverSeqNumToMessage.TryGetValue(fragment.SequenceNumber, out var message))
            _serverSeqNumToMessage[fragment.SequenceNumber] = message = new HandshakeMessage(fragment);

        if (message.Handshake is null)
            message.AddFragment(fragment);

        if (message.Handshake is not null)
            _handshakeTypeToMessage[message.Handshake.Type] = message;
    }

    private void ProcessServerHello(ServerHelloHandshake serverHello)
    {
        if (State is not EClientHandshakeState.WAITING_SERVER_HELLO)
            return;

        if (serverHello.CipherSuite is not ECipherSuite.TLS_AES_128_GCM_SHA256)
            throw new FormatException("Server selected unsupported cipher suite");

        var supportedVersions = serverHello.Extensions.FirstOrDefault(x => x is SupportedVersionsExtension) as SupportedVersionsExtension;
        if (supportedVersions is null)
            throw new FormatException("The server did not include the required 'Supported Versions' extension");
        if (!supportedVersions.Versions.Contains(EVersions.DTLS1_3))
            throw new FormatException("Unsupported DTLS version");

        var keyShare = serverHello.Extensions.FirstOrDefault(x => x is KeyShareExtension) as KeyShareExtension;
        if (keyShare is null)
            throw new FormatException("The server did not include the required 'Key Share' extension");
        if (!keyShare.GroupToKey.ContainsKey(ENamedGroup.X25519))
            throw new FormatException("Unsupported key exchange algorithm");

        var key = keyShare.GroupToKey[ENamedGroup.X25519];
        if (key.Length != 32)
            throw new FormatException("Invalid X25519 public key length");

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            throw new Exception();
        if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
            throw new Exception();

        _serverPublicKey = key;
        _helloHash = KeyHashHelper.HashFragments([clientHelloMessage.GetFragment(), serverHelloMessage.GetFragment()]);
        _sharedSecret = KeyHashHelper.SharedSecret(_privateKey, _serverPublicKey);

        var zeros = new byte[32];
        var earlySecret = KeyHashHelper.HKDF_Extract(zeros, zeros);
        var emptyHash = SHA256.HashData(Array.Empty<byte>());
        var derived = KeyHashHelper.HKDF_ExpandLabel(earlySecret, "derived", emptyHash, _helloHash.Length, KeyHashHelper.DTLS_PREFIX);

        _handshakeSecret = KeyHashHelper.HKDF_Extract(derived, _sharedSecret);
        _clientSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "c hs traffic", _helloHash, KeyHashHelper.DTLS_PREFIX);
        _serverSecret = KeyHashHelper.DeriveSecret(_handshakeSecret, "s hs traffic", _helloHash, KeyHashHelper.DTLS_PREFIX);

        _clientHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        _clientHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        _serverHandshakeKey = KeyHashHelper.HKDF_ExpandLabel(_serverSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        _serverHandshakeIV = KeyHashHelper.HKDF_ExpandLabel(_serverSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        _clientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(_clientSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        _serverRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(_serverSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);

        _serverHandshakeAes?.Dispose();
        _serverRecordNumberAes?.Dispose();

        _serverHandshakeAes = new AesGcm(_serverHandshakeKey, AesGcm.TagByteSizes.MaxSize);

        _serverRecordNumberAes = Aes.Create();
        _serverRecordNumberAes.KeySize = 128;
        _serverRecordNumberAes.Key = _serverRecordNumberKey;
        _serverRecordNumberAes.Mode = CipherMode.ECB;
        _serverRecordNumberAes.Padding = PaddingMode.None;

        State = EClientHandshakeState.WAITING_ENCRYPTED_EXTENSIONS;
    }

    private void ProcessEncryptedExtensions(EncryptedExtensionsHandshake encryptedExtensions)
    {
        if (State is not EClientHandshakeState.WAITING_ENCRYPTED_EXTENSIONS)
            return;

        var supportedGroups = encryptedExtensions.Extensions.FirstOrDefault(x => x is SupportedGroupsExtension) as SupportedGroupsExtension;
        if (supportedGroups is null)
            throw new FormatException("Server did not include required extension - Supported Groups");
        if (!supportedGroups.Groups.Contains(ENamedGroup.X25519))
            throw new FormatException("Unsupported curve algorithm");

        State = EClientHandshakeState.WAITING_CERTIFICATE;
    }

    private void ProcessServerCertificate(ServerCertificateHandshake serverCertificate)
    {
        if (State is not EClientHandshakeState.WAITING_CERTIFICATE)
            return;

        var certificates = serverCertificate.Certificates.Select(x => x.ToX509Certificate2()).ToArray();

        try
        {
            var domain = RendezvousServerDomain();

            if (!ValidateCertificates(certificates, domain))
                throw new AuthenticationException("Certificate validation failed");

            _serverCertificate = certificates.FirstOrDefault(x => CertificateHelper.MatchesDomain(x, domain));

            if (_serverCertificate is null)
                throw new AuthenticationException("Certificate validation failed (no certificates with the matching domain)");

            State = EClientHandshakeState.WAITING_CERTIFICATE_VERIFY;
        }
        finally
        {
            foreach (var certificate in certificates)
                if (certificate != _serverCertificate)
                    certificate.Dispose();
        }
    }

    private void ProcessServerCertVerify(ServerCertVerifyHandshake serverCertVerify)
    {
        if (State is not EClientHandshakeState.WAITING_CERTIFICATE_VERIFY)
            return;

        if (_serverCertificate is null)
            throw new NullReferenceException("Server certificate verification was received before the server certificate itself");

        if (serverCertVerify.Algorithm is not ESignatureAlgorithm.ECDSA_SECP256R1_SHA256)
            throw new NotSupportedException("The server used an unsupported signature algorithm");

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            throw new InvalidOperationException("ClientHello handshake message is missing from handshake transcript");
        if (clientHelloMessage.Handshake is not ClientHelloHandshake)
            throw new InvalidOperationException("Expected ClientHello handshake message at sequence 0");

        if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
            throw new InvalidOperationException("ServerHello handshake message is missing from handshake transcript");
        if (serverHelloMessage.Handshake is not ServerHelloHandshake)
            throw new InvalidOperationException("Expected ServerHello handshake message at sequence 0");

        if (!_serverSeqNumToMessage.TryGetValue(1, out var encryptedExtensionsMessage))
            throw new InvalidOperationException("EncryptedExtensions handshake message is missing from handshake transcript");
        if (encryptedExtensionsMessage.Handshake is not EncryptedExtensionsHandshake)
            throw new InvalidOperationException("Expected EncryptedExtensions handshake message at sequence 1");

        if (!_serverSeqNumToMessage.TryGetValue(2, out var serverCertificateMessage))
            throw new InvalidOperationException("ServerCertificate handshake message is missing from handshake transcript");
        if (serverCertificateMessage.Handshake is not ServerCertificateHandshake)
            throw new InvalidOperationException("Expected ServerCertificate handshake message at sequence 2");

        var hash = KeyHashHelper.HashFragments(
            [
                clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment()
            ]
        );

        var length = KeyHashHelper.CERT_VERIFY_PREFIX.Length + hash.Length;
        Span<byte> buffer = length < 1024 ? stackalloc byte[length] : new byte[length];
        KeyHashHelper.CERT_VERIFY_PREFIX.CopyTo(buffer.Slice(0, KeyHashHelper.CERT_VERIFY_PREFIX.Length));
        hash.CopyTo(buffer.Slice(KeyHashHelper.CERT_VERIFY_PREFIX.Length, hash.Length));

        using var ecdsa = _serverCertificate.GetECDsaPublicKey();
        if (ecdsa is null)
            throw new InvalidOperationException("The server certificate does not contain an ECDsa public key");

        if (!ecdsa.VerifyData(buffer, serverCertVerify.Signature.AsSpan(), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            throw new AuthenticationException("The server's CertificateVerify signature failed verification");

        State = EClientHandshakeState.WAITING_HANDSHAKE_FINISHED;
    }

    private async Task ProcessServerFinishedAsync(FinishedHandshake finished, CancellationToken ct)
    {
        if (State is not EClientHandshakeState.WAITING_HANDSHAKE_FINISHED)
            return;

        if (_handshakeSecret is null)
            throw new NullReferenceException("Handshake secret has not been derived");
        if (_serverSecret is null)
            throw new NullReferenceException("Server Finished message received before deriving the server handshake secret");

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            throw new InvalidOperationException("ClientHello handshake message is missing from handshake transcript");
        if (clientHelloMessage.Handshake is not ClientHelloHandshake)
            throw new InvalidOperationException("Expected ClientHello handshake message at sequence 0");

        if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
            throw new InvalidOperationException("ServerHello handshake message is missing from handshake transcript");
        if (serverHelloMessage.Handshake is not ServerHelloHandshake)
            throw new InvalidOperationException("Expected ServerHello handshake message at sequence 0");

        if (!_serverSeqNumToMessage.TryGetValue(1, out var encryptedExtensionsMessage))
            throw new InvalidOperationException("EncryptedExtensions handshake message is missing from handshake transcript");
        if (encryptedExtensionsMessage.Handshake is not EncryptedExtensionsHandshake)
            throw new InvalidOperationException("Expected EncryptedExtensions handshake message at sequence 1");

        if (!_serverSeqNumToMessage.TryGetValue(2, out var serverCertificateMessage))
            throw new InvalidOperationException("ServerCertificate handshake message is missing from handshake transcript");
        if (serverCertificateMessage.Handshake is not ServerCertificateHandshake)
            throw new InvalidOperationException("Expected ServerCertificate handshake message at sequence 2");

        if (!_serverSeqNumToMessage.TryGetValue(3, out var serverCertVerifyMessage))
            throw new InvalidOperationException("ServerCertVerify handshake message is missing from handshake transcript");
        if (serverCertVerifyMessage.Handshake is not ServerCertVerifyHandshake)
            throw new InvalidOperationException("Expected ServerCertVerify handshake message at sequence 3");

        if (!_serverSeqNumToMessage.TryGetValue(4, out var serverFinishedMessage))
            throw new InvalidOperationException("ServerFinished handshake message is missing from handshake transcript");
        if (serverFinishedMessage.Handshake is not FinishedHandshake)
            throw new InvalidOperationException("Expected ServerFinished handshake message at sequence 4");

        var finishedKey = KeyHashHelper.HKDF_ExpandLabel(_serverSecret, "finished", Array.Empty<byte>(), 32, KeyHashHelper.DTLS_PREFIX);
        var hash = KeyHashHelper.HashFragments(
            [
                clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment(),
                serverCertVerifyMessage.GetFragment()
            ]
        );

        var verifyData = HMACSHA256.HashData(finishedKey, hash);

        if (!CryptographicOperations.FixedTimeEquals(finished.VerifyData, verifyData))
            throw new AuthenticationException("Server Finished message verification failed");

        var handshakeHash = KeyHashHelper.HashFragments(
            [
                clientHelloMessage.GetFragment(),
                serverHelloMessage.GetFragment(),
                encryptedExtensionsMessage.GetFragment(),
                serverCertificateMessage.GetFragment(),
                serverCertVerifyMessage.GetFragment(),
                serverFinishedMessage.GetFragment()
            ]
        );

        var zeros = new byte[32];
        var derivedSecret = KeyHashHelper.HKDF_ExpandLabel(_handshakeSecret, "derived", Array.Empty<byte>(), 32, KeyHashHelper.DTLS_PREFIX);
        var masterSecret = KeyHashHelper.HKDF_Extract(derivedSecret, zeros);
        var clientSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "c ap traffic", handshakeHash, 32, KeyHashHelper.DTLS_PREFIX);
        var serverSecret = KeyHashHelper.HKDF_ExpandLabel(masterSecret, "s ap traffic", handshakeHash, 32, KeyHashHelper.DTLS_PREFIX);

        ClientApplicationKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ServerApplicationKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "key", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ClientApplicationIV = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        ServerApplicationIV = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "iv", Array.Empty<byte>(), 12, KeyHashHelper.DTLS_PREFIX);
        ClientRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(clientSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);
        ServerRecordNumberKey = KeyHashHelper.HKDF_ExpandLabel(serverSecret, "sn", Array.Empty<byte>(), 16, KeyHashHelper.DTLS_PREFIX);

        await SendClientFinishedAsync(ct);

        State = EClientHandshakeState.WAITING_ACK;
    }

    private void ProcessServerAck()
    {
        if (State is not EClientHandshakeState.WAITING_ACK)
            return;

        State = EClientHandshakeState.DONE;
    }

    private async Task SendClientHelloAsync(CancellationToken ct)
    {
        if (_clientHello is null)
            throw new NullReferenceException("Failed to send client hello: _clientHello was null");

        if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
            _clientSeqNumToMessage[0] = clientHelloMessage = new HandshakeMessage(_clientHello, 0);

        var fragments = clientHelloMessage.GetFragments(Math.Max(39, PacketMtu() - 25));
        for(uint i = 0; i < fragments.Length; i++)
        {
            var fragment = fragments[i];
            var fragmentBuffer = new byte[fragment.Length()];
            fragment.Write(fragmentBuffer);

            var record = new PlainTextRecord(fragmentBuffer)
            {
                Type = ERecordType.HANDSHAKE,
                Epoch = 0,
                RecordNumber = i
            };
            var recordBuffer = new byte[record.Length()];
            record.Write(recordBuffer);
            await SendAsync(recordBuffer, ct);
        }
    }

    private async Task SendClientFinishedAsync(CancellationToken ct)
    {
        if (_clientHandshakeKey is null)
            throw new NullReferenceException("Client handshake key has not been derived");
        if (_clientHandshakeIV is null)
            throw new NullReferenceException("Client handshake IV has not been derived");
        if (_clientRecordNumberKey is null)
            throw new NullReferenceException("Client record number encryption key has not been derived");

        if (!_clientSeqNumToMessage.TryGetValue(1, out var clientFinishedMessage))
        {
            if (_clientSecret is null)
                throw new NullReferenceException("Client handshake secret has not been derived");

            if (!_clientSeqNumToMessage.TryGetValue(0, out var clientHelloMessage))
                throw new InvalidOperationException("ClientHello handshake message is missing from handshake transcript");
            if (clientHelloMessage.Handshake is not ClientHelloHandshake)
                throw new InvalidOperationException("Expected ClientHello handshake message at sequence 0");

            if (!_serverSeqNumToMessage.TryGetValue(0, out var serverHelloMessage))
                throw new InvalidOperationException("ServerHello handshake message is missing from handshake transcript");
            if (serverHelloMessage.Handshake is not ServerHelloHandshake)
                throw new InvalidOperationException("Expected ServerHello handshake message at sequence 0");

            if (!_serverSeqNumToMessage.TryGetValue(1, out var encryptedExtensionsMessage))
                throw new InvalidOperationException("EncryptedExtensions handshake message is missing from handshake transcript");
            if (encryptedExtensionsMessage.Handshake is not EncryptedExtensionsHandshake)
                throw new InvalidOperationException("Expected EncryptedExtensions handshake message at sequence 1");

            if (!_serverSeqNumToMessage.TryGetValue(2, out var serverCertificateMessage))
                throw new InvalidOperationException("ServerCertificate handshake message is missing from handshake transcript");
            if (serverCertificateMessage.Handshake is not ServerCertificateHandshake)
                throw new InvalidOperationException("Expected ServerCertificate handshake message at sequence 2");

            if (!_serverSeqNumToMessage.TryGetValue(3, out var serverCertVerifyMessage))
                throw new InvalidOperationException("ServerCertVerify handshake message is missing from handshake transcript");
            if (serverCertVerifyMessage.Handshake is not ServerCertVerifyHandshake)
                throw new InvalidOperationException("Expected ServerCertVerify handshake message at sequence 3");

            if (!_serverSeqNumToMessage.TryGetValue(4, out var serverFinishedMessage))
                throw new InvalidOperationException("ServerFinished handshake message is missing from handshake transcript");
            if (serverFinishedMessage.Handshake is not FinishedHandshake)
                throw new InvalidOperationException("Expected ServerFinished handshake message at sequence 4");

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

            _clientSeqNumToMessage[1] = clientFinishedMessage = new HandshakeMessage(new FinishedHandshake(verifyData), 1);
        }

        _clientHandshakeAes?.Dispose();
        _clientRecordNumberAes?.Dispose();

        _clientHandshakeAes = new AesGcm(_clientHandshakeKey, AesGcm.TagByteSizes.MaxSize);

        _clientRecordNumberAes = Aes.Create();
        _clientRecordNumberAes.KeySize = 128;
        _clientRecordNumberAes.Key = _clientRecordNumberKey;
        _clientRecordNumberAes.Mode = CipherMode.ECB;
        _clientRecordNumberAes.Padding = PaddingMode.None;

        var fragments = clientFinishedMessage.GetFragments(Math.Max(30, PacketMtu() - 34));
        for (uint i = 0; i < fragments.Length; i++)
        {
            var fragment = fragments[i];
            var fragmentBuffer = new byte[fragment.Length()];
            fragment.Write(fragmentBuffer);

            var record = new CipherTextRecord(fragmentBuffer)
            {
                RecordNumber = i,
                Epoch = 2,
                Type = ERecordType.HANDSHAKE
            };
            var recordBuffer = new byte[record.Length()];
            record.EncryptAndWrite(recordBuffer, _clientHandshakeAes, _clientHandshakeIV, _clientRecordNumberAes);
            await SendAsync(recordBuffer, ct);
        }
    }

    private Task ResendAsync(CancellationToken ct)
    {
        switch (State)
        {
            case EClientHandshakeState.WAITING_SERVER_HELLO:
            case EClientHandshakeState.WAITING_ENCRYPTED_EXTENSIONS:
            case EClientHandshakeState.WAITING_CERTIFICATE:
            case EClientHandshakeState.WAITING_CERTIFICATE_VERIFY:
            case EClientHandshakeState.WAITING_HANDSHAKE_FINISHED:
                return SendClientHelloAsync(ct);
            case EClientHandshakeState.WAITING_ACK:
                return SendClientFinishedAsync(ct);
        }

        return Task.CompletedTask;
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
            RecordNumber = 1
        };
        var recordBuffer = new byte[record.Length()];
        record.Write(recordBuffer);

        return recordBuffer;
    }

    public byte[]? GetAlertCipherText(EAlertType type)
    {
        if (_clientHandshakeAes is null)
            return null;
        if (_clientHandshakeIV is null)
            return null;
        if (_clientRecordNumberAes is null)
            return null;

        var alert = new Alert(type);
        var alertBuffer = new byte[alert.Length()];
        alert.Write(alertBuffer);

        var record = new CipherTextRecord(alertBuffer)
        {
            Type = ERecordType.ALERT,
            Epoch = 2,
            RecordNumber = 1
        };
        var recordBuffer = new byte[record.Length()];
        record.EncryptAndWrite(recordBuffer, _clientHandshakeAes, _clientHandshakeIV, _clientRecordNumberAes);

        return recordBuffer;
    }

    protected virtual bool ValidateCertificates(X509Certificate2[] certificates, string domain)
        => CertificateHelper.ValidateCertificatesForDomain(certificates, domain);

    protected abstract int PacketMtu();
    protected abstract string RendezvousServerDomain();
    protected abstract Task SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct);
    protected abstract Task<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct);

    public void Dispose()
    {
        Reset(true);
    }
}
