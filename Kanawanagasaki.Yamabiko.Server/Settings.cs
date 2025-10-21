namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

public static class Settings
{
    public static int Port { get; set; } = 9999;
    public static int MTU { get; set; } = 1400;
    public static string Domain { get; set; } = "example.com";

    private static X509Certificate2? _selfSignedCertificate;
    public static X509Certificate2 SelfSignedCertificate
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

    public static string? CertificatePath { get; set; }
    private static X509Certificate2? _certificate;
    private static long _lastCertificateCheck = 0;
    public static X509Certificate2 Certificate
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

    public static int MaxClients { get; set; } = 1024;
    public static int MaxClientsPerRemoteNetwork { get; set; } = 8;

    public static int MaxInactivitySeconds { get; set; } = 90;
}
