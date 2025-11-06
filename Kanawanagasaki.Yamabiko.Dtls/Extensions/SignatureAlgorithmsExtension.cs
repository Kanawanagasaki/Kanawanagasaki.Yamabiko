namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class SignatureAlgorithmsExtension : IExtension
{
    internal const EExtensionType TYPE = EExtensionType.SIGNATURE_ALGORITHMS;
    public EExtensionType Type => TYPE;

    internal ESignatureAlgorithm[] Algorithms { get; }

    internal SignatureAlgorithmsExtension(ESignatureAlgorithm[] algorithms)
    {
        Algorithms = algorithms;
    }

    public int Length(bool isRequest)
    {
        if (isRequest)
            return 2 + Algorithms.Length * 2;
        else
            return Algorithms.Length * 2;
    }

    public void Write(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < Length(isRequest))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        var len = Algorithms.Length * 2;
        if (ushort.MaxValue < len)
            throw new FormatException($"Extension data length exceeds {ushort.MaxValue} bytes");

        if (isRequest)
        {
            buffer[offset++] = (byte)((len >> 8) & 0xFF);
            buffer[offset++] = (byte)(len & 0xFF);
        }

        for (int i = 0; i < Algorithms.Length; i++)
        {
            var algorithmNum = (ushort)Algorithms[i];
            buffer[offset++] = (byte)(algorithmNum >> 8);
            buffer[offset++] = (byte)(algorithmNum & 0xFF);
        }
    }

    internal static SignatureAlgorithmsExtension Parse(Span<byte> buffer, bool isRequest)
    {
        int offset = 0;

        int len;
        if (isRequest)
            len = (buffer[offset++] << 8) | buffer[offset++];
        else
            len = buffer.Length;
        var dataEnd = offset + len;

        if (buffer.Length < dataEnd)
            throw new FormatException("Extension data length exceeds available buffer size");

        if (len % 2 != 0)
            throw new FormatException("Extension data length must be even");

        var algorithms = new ESignatureAlgorithm[len / 2];

        if (algorithms.Length == 0)
            throw new FormatException("At least one algorithm must be specified");

        for (int i = 0; i < algorithms.Length; i++)
        {
            var algorithmNum = (buffer[offset++] << 8) | buffer[offset++];
            var algorithm = (ESignatureAlgorithm)algorithmNum;

            if (!Enum.IsDefined(algorithm))
                throw new FormatException($"Unsupported or invalid algorithm: 0x{algorithmNum:X4}");

            algorithms[i] = algorithm;
        }

        return new SignatureAlgorithmsExtension(algorithms);
    }
}
