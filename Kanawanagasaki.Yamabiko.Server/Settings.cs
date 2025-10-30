namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

public class Settings
{
    public int Port { get; set; } = 9999;
    public int MTU { get; set; } = 1400;
    public string Domain { get; set; } = "example.com";

    private X509Certificate2? _selfSignedCertificate;
    public X509Certificate2 SelfSignedCertificate
    {
        get
        {
            if (_selfSignedCertificate is null)
                _selfSignedCertificate = CertificateHelper.GenerateSelfSignedCertificate(Domain);
            if (!CertificateHelper.MatchesDomain(_selfSignedCertificate, Domain))
            {
                _selfSignedCertificate.Dispose();
                _selfSignedCertificate = CertificateHelper.GenerateSelfSignedCertificate(Domain);
            }
            return _selfSignedCertificate;
        }
    }

    public string? CertificatePath { get; set; }
    private X509Certificate2? _certificate;
    private long _lastCertificateCheck = 0;
    public X509Certificate2 Certificate
    {
        get
        {
            var now = DateTime.UtcNow;
            if (_certificate is not null && (now < _certificate.NotBefore || _certificate.NotAfter < now))
            {
                _certificate.Dispose();
                _certificate = null;
            }

            if (_certificate is null
                && TimeSpan.FromHours(1) < Stopwatch.GetElapsedTime(_lastCertificateCheck)
                && CertificatePath is not null
                && File.Exists(CertificatePath))
            {
                _lastCertificateCheck = Stopwatch.GetTimestamp();

                var certificate = X509CertificateLoader.LoadCertificateFromFile(CertificatePath);
                if (certificate.Verify() && certificate.NotBefore < now && now < certificate.NotAfter)
                    _certificate = certificate;
                else
                    certificate.Dispose();
            }

            return _certificate ?? SelfSignedCertificate;
        }
    }

    public int MaxClients { get; set; } = 1024;
    public int MaxClientsPerRemoteNetwork { get; set; } = 8;

    public int MaxInactivitySeconds { get; set; } = 90;
}
