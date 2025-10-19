namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;
using System.Text;

public class ConnectPacket : Packet
{
    public const EPacketType TYPE = EPacketType.CONNECT;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    private byte[] _passwordBytes = Array.Empty<byte>();
    private string? _password;
    public string? Password
    {
        get => _password;
        init
        {
            _password = value;
            if (value is not null)
                _passwordBytes = Encoding.UTF8.GetBytes(value);
        }
    }

    public required byte[] PublicKey { get; init; }

    public ConnectPacket() { }

    private ConnectPacket(byte[] passwordBytes)
    {
        _passwordBytes = passwordBytes;
        if (0 < passwordBytes.Length)
            _password = Encoding.UTF8.GetString(passwordBytes);
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += 16; // peer id

        len += 1 + _passwordBytes.Length;

        len += 1 + PublicKey.Length;

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        PeerId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        buffer[offset++] = (byte)_passwordBytes.Length;
        _passwordBytes.CopyTo(buffer.Slice(offset, (byte)_passwordBytes.Length));
        offset += (byte)_passwordBytes.Length;

        buffer[offset++] = (byte)PublicKey.Length;
        PublicKey.CopyTo(buffer.Slice(offset, (byte)PublicKey.Length));
    }

    public static ConnectPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too small: cannot read peer id");
        var peerId = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read password length");
        var passwordLength = buffer[offset++];
        if (buffer.Length < offset + passwordLength)
            throw new FormatException("Buffer too small: cannot read password");
        var passwordSpan = buffer.Slice(offset, passwordLength);
        offset += passwordLength;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read public key length");
        var publicKeyLength = buffer[offset++];
        if (buffer.Length < offset + publicKeyLength)
            throw new FormatException("Buffer too small: cannot read public key");
        var publicKeySpan = buffer.Slice(offset, publicKeyLength);

        return new ConnectPacket(passwordSpan.ToArray())
        {
            PeerId = peerId,
            PublicKey = publicKeySpan.ToArray()
        };
    }
}
