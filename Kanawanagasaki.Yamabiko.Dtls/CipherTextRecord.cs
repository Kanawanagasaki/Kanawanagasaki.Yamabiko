namespace Kanawanagasaki.Yamabiko.Dtls;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Security.Cryptography;

public class CipherTextRecord
{
    public const byte HEADER_BITS = 0b0010_0000;

    public required ushort RecordNumber { get; init; }
    public required byte EpochLowBits { get; init; }

    public byte[]? ConnectionId { get; init; }

    public byte[] Buffer { get; }

    public required ERecordType Type { get; init; }

    public CipherTextRecord(byte[] buffer)
    {
        Buffer = buffer;
    }

    public int Length()
    {
        int len = 0;

        len += 1; // Header

        if (ConnectionId is not null)
            len += ConnectionId.Length;

        len += 2; // Sequence number

        len += 2; // Record length

        len += Buffer.Length;

        len += AesGcm.TagByteSizes.MaxSize;

        len += 1;

        return len;
    }

    public void EncryptAndWrite(Span<byte> buffer, AesGcm aes, Span<byte> iv, Aes headerAes)
    {
        if (aes.TagSizeInBytes != AesGcm.TagByteSizes.MaxSize)
            throw new ArgumentException($"Tag size in bytes must be {AesGcm.TagByteSizes.MaxSize} bytes long", nameof(aes));
        if (iv.Length != AesGcm.NonceByteSizes.MaxSize)
            throw new ArgumentException($"IV must be {AesGcm.NonceByteSizes.MaxSize} bytes long", nameof(iv));
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        var sequenceNumOffset = 1 + (ConnectionId is not null ? ConnectionId.Length : 0);
        var encryptedOffset = sequenceNumOffset + 4;
        var headerSpan = buffer[..encryptedOffset];
        var encryptedSpan = buffer.Slice(encryptedOffset, Buffer.Length + 1);
        var tagSpan = buffer.Slice(encryptedOffset + Buffer.Length + 1, AesGcm.TagByteSizes.MaxSize);

        int offset = 0;

        var headerFlags = EHeaderFlags.IS_SEQUENCE_NUMBER_2_BYTES | EHeaderFlags.HAS_LENGTH_FIELD;
        if (ConnectionId is not null)
            headerFlags |= EHeaderFlags.HAS_CONNECTION_ID;
        headerSpan[offset++] = (byte)((byte)headerFlags | HEADER_BITS | (EpochLowBits & 0b11));

        if (ConnectionId is not null)
        {
            ConnectionId.CopyTo(headerSpan[offset..]);
            offset += ConnectionId.Length;
        }

        headerSpan[offset++] = (byte)(RecordNumber >> 8);
        headerSpan[offset++] = (byte)(RecordNumber & 0xFF);

        var recordLen = Buffer.Length + 1 + AesGcm.TagByteSizes.MaxSize;
        headerSpan[offset++] = (byte)((recordLen >> 8) & 0xFF);
        headerSpan[offset++] = (byte)(recordLen & 0xFF);

        Span<byte> recordIv = stackalloc byte[iv.Length];
        iv.CopyTo(recordIv);
        recordIv[^2] ^= (byte)((RecordNumber >> 8) & 0xFF);
        recordIv[^1] ^= (byte)(RecordNumber & 0xFF);

        Span<byte> data = Buffer.Length < 1023 ? stackalloc byte[Buffer.Length + 1] : new byte[Buffer.Length + 1];
        Buffer.CopyTo(data);
        data[^1] = (byte)Type;

        aes.Encrypt(recordIv, data, encryptedSpan, tagSpan, headerSpan);

        using var encryptor = headerAes.CreateEncryptor();

        var sample = buffer.Slice(encryptedOffset, 16).ToArray();
        var transformer = encryptor.TransformFinalBlock(sample, 0, sample.Length);

        headerSpan[sequenceNumOffset] ^= transformer[0];
        headerSpan[sequenceNumOffset + 1] ^= transformer[1];
    }

    public static CipherTextRecord DecryptAndParse(ReadOnlySpan<byte> buffer, AesGcm aes, ReadOnlySpan<byte> iv, Aes headerAes, ref int offset)
        => DecryptAndParse(buffer, aes, iv, headerAes, null, ref offset);
    public static CipherTextRecord DecryptAndParse(ReadOnlySpan<byte> buffer, AesGcm aes, ReadOnlySpan<byte> iv, Aes headerAes, int? connectionIdLength, ref int offset)
    {
        int startOffset = offset;

        if (aes.TagSizeInBytes != AesGcm.TagByteSizes.MaxSize)
            throw new ArgumentException($"Tag size in bytes must be {AesGcm.TagByteSizes.MaxSize} bytes long", nameof(aes));
        if (iv.Length != AesGcm.NonceByteSizes.MaxSize)
            throw new ArgumentException($"IV must be {AesGcm.NonceByteSizes.MaxSize} bytes long", nameof(iv));
        if (buffer.Length < offset + 5)
            throw new FormatException("Buffer too small");

        if ((buffer[offset] & (byte)EHeaderFlags.FIXED_BITS) != HEADER_BITS)
            throw new FormatException("Malformed record: first three bits must be 001");

        var epoch = (byte)(buffer[offset] & (byte)EHeaderFlags.ENCRYPTION_EPOCH);
        var header = (EHeaderFlags)buffer[offset++];

        if (header.HasFlag(EHeaderFlags.HAS_CONNECTION_ID) != connectionIdLength.HasValue)
            throw new FormatException("Mismatch between connection ID expectations");

        byte[]? connectionId = null;
        if (connectionIdLength.HasValue)
        {
            if (buffer.Length < offset + connectionIdLength)
                throw new FormatException("Buffer too small to read connection ID");
            connectionId = buffer.Slice(offset, connectionIdLength.Value).ToArray();
            offset += connectionIdLength.Value;
        }

        var sequenceNumOffset = offset;
        Span<byte> sequenceNumBytes;
        if (header.HasFlag(EHeaderFlags.IS_SEQUENCE_NUMBER_2_BYTES))
        {
            if (buffer.Length < offset + 2)
                throw new FormatException("Buffer too small to read sequence number");
            sequenceNumBytes = new byte[2];
            buffer.Slice(offset, 2).CopyTo(sequenceNumBytes);
            offset += 2;
        }
        else
        {
            if (buffer.Length < offset + 1)
                throw new FormatException("Buffer too small to read sequence number");
            sequenceNumBytes = new byte[1];
            buffer.Slice(offset, 1).CopyTo(sequenceNumBytes);
            offset++;
        }

        int length;
        if (header.HasFlag(EHeaderFlags.HAS_LENGTH_FIELD))
        {
            if (buffer.Length < offset + 2)
                throw new FormatException("Buffer too small to read length");
            length = (ushort)((buffer[offset++] << 8) | buffer[offset++]);
        }
        else
            length = buffer.Length - offset;

        if (length < AesGcm.TagByteSizes.MaxSize)
            throw new FormatException("Length too short: cannot accommodate the authentication tag");

        if (buffer.Length < offset + length)
            throw new FormatException("Buffer too small to read encrypted data");

        var encryptedSpan = buffer.Slice(offset, length - AesGcm.TagByteSizes.MaxSize);
        var tagSpan = buffer.Slice(offset + length - AesGcm.TagByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize);

        using var encryptor = headerAes.CreateEncryptor();

        var sample = buffer.Slice(offset, 16).ToArray();
        var transformer = encryptor.TransformFinalBlock(sample, 0, sample.Length);

        for (int i = 0; i < sequenceNumBytes.Length; i++)
            sequenceNumBytes[i] ^= transformer[i];

        ushort sequenceNum;
        if (sequenceNumBytes.Length == 2)
            sequenceNum = (ushort)((sequenceNumBytes[0] << 8) | sequenceNumBytes[1]);
        else
            sequenceNum = sequenceNumBytes[0];

        Span<byte> recordIv = stackalloc byte[iv.Length];
        iv.CopyTo(recordIv);
        for (int i = 1; i <= sequenceNumBytes.Length && i <= recordIv.Length; i++)
            recordIv[^i] ^= sequenceNumBytes[^i];

        Span<byte> associatedData = stackalloc byte[offset - startOffset];
        buffer[startOffset..offset].CopyTo(associatedData);
        for (int i = 0; i < sequenceNumBytes.Length; i++)
            associatedData[sequenceNumOffset + i - startOffset] = sequenceNumBytes[i];

        var data = new byte[encryptedSpan.Length];
        aes.Decrypt(recordIv, encryptedSpan, tagSpan, data, associatedData);

        var recordType = (ERecordType)data[^1];
        if (!Enum.IsDefined(recordType))
            throw new FormatException("Unknown record type");

        offset += length;

        return new CipherTextRecord(data[..^1])
        {
            Type = recordType,
            EpochLowBits = epoch,
            RecordNumber = sequenceNum,
            ConnectionId = connectionId
        };
    }
}
