namespace Kanawanagasaki.Yamabiko.Dtls;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Security.Cryptography;

public class CipherTextRecord
{
    public const byte HEADER_BITS = 0b0010_0000;

    public required ulong RecordNumber { get; init; }
    public required ulong Epoch { get; init; }

    public byte[]? ConnectionId { get; init; }

    public ReadOnlyMemory<byte> Buffer { get; }

    public required ERecordType Type { get; init; }

    public CipherTextRecord(ReadOnlyMemory<byte> buffer)
    {
        Buffer = buffer;
    }

    public int Length()
        => Length(true, true);
    public int Length(bool isRecordNumber2Bytes, bool hasLengthField)
    {
        int len = 0;

        len += 1; // Header

        if (ConnectionId is not null)
            len += ConnectionId.Length;

        len += isRecordNumber2Bytes ? 2 : 1; // Record number

        if (hasLengthField)
            len += 2; // Record length

        len += Buffer.Length;

        len += AesGcm.TagByteSizes.MaxSize;

        len += 1; // Record type

        return len;
    }

    public void EncryptAndWrite(Span<byte> buffer, AesGcm aes, Span<byte> iv, Aes headerAes)
        => EncryptAndWrite(buffer, aes, iv, headerAes, true, true);
    public void EncryptAndWrite(Span<byte> buffer, AesGcm aes, Span<byte> iv, Aes headerAes, bool isRecordNumber2Bytes, bool hasLengthField)
    {
        if (aes.TagSizeInBytes != AesGcm.TagByteSizes.MaxSize)
            throw new ArgumentException($"Tag size in bytes must be {AesGcm.TagByteSizes.MaxSize} bytes long", nameof(aes));
        if (iv.Length != AesGcm.NonceByteSizes.MaxSize)
            throw new ArgumentException($"IV must be {AesGcm.NonceByteSizes.MaxSize} bytes long", nameof(iv));
        if (headerAes.Mode != CipherMode.ECB || headerAes.Padding != PaddingMode.None)
            throw new ArgumentException("Header Aes must be configured as AES-ECB with PaddingMode.None", nameof(headerAes));
        if (buffer.Length < Length(isRecordNumber2Bytes, hasLengthField))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        var recordNumOffset = 1 + (ConnectionId is not null ? ConnectionId.Length : 0);
        var encryptedOffset = recordNumOffset + (isRecordNumber2Bytes ? 2 : 1) + (hasLengthField ? 2 : 0);
        var headerSpan = buffer[..encryptedOffset];
        var encryptedSpan = buffer.Slice(encryptedOffset, Buffer.Length + 1);
        var tagSpan = buffer.Slice(encryptedOffset + Buffer.Length + 1, AesGcm.TagByteSizes.MaxSize);

        int offset = 0;

        var headerFlags = EHeaderFlags.NONE;
        if (isRecordNumber2Bytes)
            headerFlags |= EHeaderFlags.IS_RECORD_NUMBER_2_BYTES;
        if (hasLengthField)
            headerFlags |= EHeaderFlags.HAS_LENGTH_FIELD;
        if (ConnectionId is not null)
            headerFlags |= EHeaderFlags.HAS_CONNECTION_ID;
        headerSpan[offset++] = (byte)(HEADER_BITS | (byte)headerFlags | (byte)(Epoch & 0b11));

        if (ConnectionId is not null)
        {
            ConnectionId.CopyTo(headerSpan[offset..]);
            offset += ConnectionId.Length;
        }

        if (isRecordNumber2Bytes)
            headerSpan[offset++] = (byte)((RecordNumber >> 8) & 0xFF);
        headerSpan[offset++] = (byte)(RecordNumber & 0xFF);

        if (hasLengthField)
        {
            var recordLen = Buffer.Length + 1 + AesGcm.TagByteSizes.MaxSize;
            headerSpan[offset++] = (byte)((recordLen >> 8) & 0xFF);
            headerSpan[offset++] = (byte)(recordLen & 0xFF);
        }

        Span<byte> recordIv = stackalloc byte[iv.Length];
        iv.CopyTo(recordIv);
        for (int i = 0; i < 8 && i < recordIv.Length; i++)
            recordIv[^(i + 1)] ^= (byte)((RecordNumber >> (i * 8)) & 0xFF);

        Span<byte> data = Buffer.Length < 1023 ? stackalloc byte[Buffer.Length + 1] : new byte[Buffer.Length + 1];
        Buffer.Span.CopyTo(data);
        data[^1] = (byte)Type;

        aes.Encrypt(recordIv, data, encryptedSpan, tagSpan, headerSpan);

        using var encryptor = headerAes.CreateEncryptor();

        var sample = buffer.Slice(encryptedOffset, 16).ToArray();
        var transformer = encryptor.TransformFinalBlock(sample, 0, sample.Length);

        headerSpan[recordNumOffset] ^= transformer[0];
        if (isRecordNumber2Bytes)
            headerSpan[recordNumOffset + 1] ^= transformer[1];
    }

    public static CipherTextRecord DecryptAndParse(ReadOnlySpan<byte> buffer, AesGcm aes, ReadOnlySpan<byte> iv, Aes headerAes, ulong epochHighBits, ulong lastRecordNum, ref int offset)
        => DecryptAndParse(buffer, aes, iv, headerAes, epochHighBits, lastRecordNum, null, ref offset);
    public static CipherTextRecord DecryptAndParse(ReadOnlySpan<byte> buffer, AesGcm aes, ReadOnlySpan<byte> iv, Aes headerAes, ulong epochHighBits, ulong lastRecordNum, int? connectionIdLength, ref int offset)
    {
        int startOffset = offset;

        if (aes.TagSizeInBytes != AesGcm.TagByteSizes.MaxSize)
            throw new ArgumentException($"Tag size in bytes must be {AesGcm.TagByteSizes.MaxSize} bytes long", nameof(aes));
        if (iv.Length != AesGcm.NonceByteSizes.MaxSize)
            throw new ArgumentException($"IV must be {AesGcm.NonceByteSizes.MaxSize} bytes long", nameof(iv));
        if (headerAes.Mode != CipherMode.ECB || headerAes.Padding != PaddingMode.None)
            throw new ArgumentException("Header Aes must be configured as AES-ECB with PaddingMode.None", nameof(headerAes));

        if ((buffer[offset] & (byte)EHeaderFlags.FIXED_BITS) != HEADER_BITS)
            throw new FormatException("Malformed record: first three bits must be 001");

        var epochLowBits = (byte)(buffer[offset] & (byte)EHeaderFlags.ENCRYPTION_EPOCH);
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

        var recordNumOffset = offset;
        Span<byte> recordNumBytes;
        if (header.HasFlag(EHeaderFlags.IS_RECORD_NUMBER_2_BYTES))
        {
            if (buffer.Length < offset + 2)
                throw new FormatException("Buffer too small to read record number");
            recordNumBytes = new byte[2];
            buffer.Slice(offset, 2).CopyTo(recordNumBytes);
            offset += 2;
        }
        else
        {
            if (buffer.Length < offset + 1)
                throw new FormatException("Buffer too small to read record number");
            recordNumBytes = new byte[1];
            buffer.Slice(offset, 1).CopyTo(recordNumBytes);
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

        for (int i = 0; i < recordNumBytes.Length; i++)
            recordNumBytes[i] ^= transformer[i];

        ulong recordNum1;
        ulong recordNum2;
        if (recordNumBytes.Length == 2)
        {
            var recordNumLowBits = (ushort)((recordNumBytes[0] << 8) | recordNumBytes[1]);
            recordNum1 = (lastRecordNum & ~0xFFFFuL) | recordNumLowBits;
            recordNum2 = recordNum1 + 0x1_00_00uL;
        }
        else
        {
            var recordNumLowBits = recordNumBytes[0];
            recordNum1 = (lastRecordNum & ~0xFFuL) | recordNumLowBits;
            recordNum2 = recordNum1 + 0x1_00uL;
        }

        ulong diff1 = lastRecordNum < recordNum1 ? recordNum1 - lastRecordNum : lastRecordNum - recordNum1;
        ulong diff2 = lastRecordNum < recordNum2 ? recordNum2 - lastRecordNum : lastRecordNum - recordNum2;
        if (diff2 < diff1)
            (recordNum1, recordNum2) = (recordNum2, recordNum1);

        var data = new byte[encryptedSpan.Length];
        ulong recordNum;

        try
        {
            Span<byte> recordIv = stackalloc byte[iv.Length];
            iv.CopyTo(recordIv);
            for (int i = 0; i < 8 && i < recordIv.Length; i++)
                recordIv[^(i + 1)] ^= (byte)((recordNum1 >> (i * 8)) & 0xFF);

            Span<byte> associatedData = stackalloc byte[offset - startOffset];
            buffer[startOffset..offset].CopyTo(associatedData);
            for (int i = 0; i < recordNumBytes.Length; i++)
                associatedData[recordNumOffset + i - startOffset] = recordNumBytes[i];

            aes.Decrypt(recordIv, encryptedSpan, tagSpan, data, associatedData);
            recordNum = recordNum1;
        }
        catch
        {
            Span<byte> recordIv = new byte[iv.Length];
            iv.CopyTo(recordIv);
            for (int i = 0; i < 8 && i < recordIv.Length; i++)
                recordIv[^(i + 1)] ^= (byte)((recordNum2 >> (i * 8)) & 0xFF);

            Span<byte> associatedData = new byte[offset - startOffset];
            buffer[startOffset..offset].CopyTo(associatedData);
            for (int i = 0; i < recordNumBytes.Length; i++)
                associatedData[recordNumOffset + i - startOffset] = recordNumBytes[i];

            aes.Decrypt(recordIv, encryptedSpan, tagSpan, data, associatedData);
            recordNum = recordNum2;
        }

        var recordType = (ERecordType)data[^1];
        if (!Enum.IsDefined(recordType))
            throw new FormatException("Unknown record type");

        offset += length;

        return new CipherTextRecord(data[..^1])
        {
            Type = recordType,
            Epoch = (epochHighBits & ~0b11uL) | epochLowBits,
            RecordNumber = recordNum,
            ConnectionId = connectionId
        };
    }

    public static ReadOnlySpan<byte> ReadConnectionId(ReadOnlySpan<byte> buffer, int connectionIdLength, int offset)
    {
        if (buffer.Length < offset + 1)
            return [];

        if ((buffer[offset] & (byte)EHeaderFlags.FIXED_BITS) != HEADER_BITS)
            return [];

        var header = (EHeaderFlags)buffer[offset++];
        if (!header.HasFlag(EHeaderFlags.HAS_CONNECTION_ID))
            return [];

        if (buffer.Length < offset + connectionIdLength)
            return [];

        return buffer.Slice(offset, connectionIdLength);
    }
}
