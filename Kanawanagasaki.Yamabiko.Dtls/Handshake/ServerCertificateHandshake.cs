namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class ServerCertificateHandshake : IHandshake
{
    internal const EHandshakeType TYPE = EHandshakeType.CERTIFICATE;
    public EHandshakeType Type => TYPE;

    internal byte[] RequestContext { get; }
    internal CertificateBuffer[] Certificates { get; }

    internal ServerCertificateHandshake(CertificateBuffer[] certificates, byte[] requestContext)
    {
        if (byte.MaxValue < requestContext.Length)
            throw new ArgumentException($"Request Context length exceeds {byte.MaxValue} bytes");

        RequestContext = requestContext;
        Certificates = certificates;
    }

    internal ServerCertificateHandshake(CertificateBuffer[] certificates)
    {
        RequestContext = Array.Empty<byte>();
        Certificates = certificates;
    }

    public int Length()
        => 1 + RequestContext.Length + 3 + Certificates.Sum(x => x.Length());

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        buffer[offset++] = (byte)RequestContext.Length;

        if (0 < RequestContext.Length)
        {
            RequestContext.CopyTo(buffer.Slice(offset, RequestContext.Length));
            offset += RequestContext.Length;
        }

        var certificatesLength = Certificates.Sum(x => x.Length());

        buffer[offset++] = (byte)((certificatesLength >> 16) & 0xFF);
        buffer[offset++] = (byte)((certificatesLength >> 8) & 0xFF);
        buffer[offset++] = (byte)(certificatesLength & 0xFF);

        foreach (var certificate in Certificates)
        {
            var certificateLength = certificate.Length();
            certificate.Write(buffer.Slice(offset, certificateLength));
            offset += certificateLength;
        }
    }

    internal static ServerCertificateHandshake Parse(Span<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read request context length");
        var requestContextLength = buffer[offset++];
        if (buffer.Length < offset + requestContextLength)
            throw new FormatException("Buffer too small: cannot read request context");

        var requestContext = buffer.Slice(offset, requestContextLength);
        offset += requestContextLength;

        if (buffer.Length < offset + 3)
            throw new FormatException("Buffer too small: cannot read certificates length");
        var certificatesLength = (buffer[offset++] << 16) | (buffer[offset++] << 8) | buffer[offset++];
        if (buffer.Length < offset + certificatesLength)
            throw new FormatException("Buffer too small: cannot read certificates");

        var certificates = new List<CertificateBuffer>();
        var dataEnd = offset + certificatesLength;
        while (offset < dataEnd)
        {
            if (dataEnd < offset + 3)
                throw new FormatException("Buffer too small: cannot read certificate length");
            var certificateLength = (buffer[offset++] << 16) | (buffer[offset++] << 8) | buffer[offset++];
            if (dataEnd < offset + certificateLength)
                throw new FormatException("Buffer too small: cannot read certificate");

            var certificate = buffer.Slice(offset, certificateLength);
            offset += certificateLength;

            if (dataEnd < offset + 2)
                throw new FormatException("Buffer too small: cannot read certificate extensions length");
            var certificateExtensionsLength = (buffer[offset++] << 8) | buffer[offset++];
            if (dataEnd < offset + certificateExtensionsLength)
                throw new FormatException("Buffer too small: cannot read certificate extensions");

            var certificateExtensions = buffer.Slice(offset, certificateExtensionsLength);
            offset += certificateExtensionsLength;

            certificates.Add(new CertificateBuffer(certificate.ToArray(), certificateExtensions.ToArray()));
        }

        return new ServerCertificateHandshake(certificates.ToArray(), requestContext.ToArray());
    }
}
