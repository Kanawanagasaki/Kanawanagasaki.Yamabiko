namespace Kanawanagasaki.Yamabiko.Dtls;

using System.Security.Cryptography.X509Certificates;

public class CertificateBuffer
{
    public byte[] Certificate { get; }
    public byte[] Extensions { get; }

    public CertificateBuffer(byte[] certificate)
    {
        if (0xFFFFFF < certificate.Length)
            throw new ArgumentException($"Certificate length exceeds {0xFFFFFF} bytes");

        Certificate = certificate;
        Extensions = Array.Empty<byte>();
    }

    public CertificateBuffer(byte[] certificate, byte[] extensions)
    {
        if (0xFFFFFF < certificate.Length)
            throw new ArgumentException($"Certificate length exceeds {0xFFFFFF} bytes");
        if (ushort.MaxValue < extensions.Length)
            throw new ArgumentException($"Extensions length exceeds {ushort.MaxValue} bytes");

        Certificate = certificate;
        Extensions = extensions;
    }

    public CertificateBuffer(X509Certificate2 certificate)
    {
        Certificate = certificate.Export(X509ContentType.Cert);
        Extensions = Array.Empty<byte>();
    }

    public CertificateBuffer(X509Certificate2 certificate, byte[] extensions)
    {
        if (ushort.MaxValue < extensions.Length)
            throw new ArgumentException($"Extensions length exceeds {ushort.MaxValue} bytes");

        Certificate = certificate.Export(X509ContentType.Cert);
        Extensions = extensions;
    }

    public int Length()
        => 3 + Certificate.Length + 2 + Extensions.Length;

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        buffer[offset++] = (byte)((Certificate.Length >> 16) & 0xFF);
        buffer[offset++] = (byte)((Certificate.Length >> 8) & 0xFF);
        buffer[offset++] = (byte)(Certificate.Length & 0xFF);

        Certificate.CopyTo(buffer.Slice(offset, Certificate.Length));
        offset += Certificate.Length;

        buffer[offset++] = (byte)((Extensions.Length >> 8) & 0xFF);
        buffer[offset++] = (byte)(Extensions.Length & 0xFF);

        Extensions.CopyTo(buffer.Slice(offset, Extensions.Length));
    }

    public X509Certificate2 ToX509Certificate2()
        => X509CertificateLoader.LoadCertificate(Certificate);
}
