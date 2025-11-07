namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System.Diagnostics;
using System.Security.Cryptography;
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
            var now = DateTimeOffset.UtcNow;
            if (_selfSignedCertificate is not null && (now < _selfSignedCertificate.NotBefore || _selfSignedCertificate.NotAfter < now))
            {
                _selfSignedCertificate.Dispose();
                _selfSignedCertificate = null;
                _privKeyECDsa?.Dispose();
                _privKeyECDsa = null;
            }
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
            var now = DateTimeOffset.UtcNow;
            if (_certificate is not null && (now < _certificate.NotBefore || _certificate.NotAfter < now))
            {
                _certificate.Dispose();
                _certificate = null;
                _privKeyECDsa?.Dispose();
                _privKeyECDsa = null;
            }

            if (_certificate is null
                && TimeSpan.FromHours(1) < Stopwatch.GetElapsedTime(_lastCertificateCheck)
                && !string.IsNullOrWhiteSpace(CertificatePath))
            {
                _lastCertificateCheck = Stopwatch.GetTimestamp();

                if (File.Exists(CertificatePath))
                {
                    Console.WriteLine($"[System] Loading certificate {CertificatePath}");

                    X509Certificate2? certificate = null;
                    try
                    {
                        certificate = X509CertificateLoader.LoadCertificateFromFile(CertificatePath);
                        if (certificate.Verify() && certificate.NotBefore < now && now < certificate.NotAfter)
                        {
                            _certificate = certificate;
                            Console.WriteLine($"[System] Certificate loaded");
                        }
                        else
                        {
                            Console.WriteLine($"[System] Certificate failed verification");
                            certificate.Dispose();
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[System] Error loading certificate: {e.Message}");
                        certificate?.Dispose();
                    }
                }
                else
                {
                    Console.WriteLine($"[System] Certificate file not found at path: {CertificatePath}");
                }

            }

            return _certificate ?? SelfSignedCertificate;
        }
    }

    public string? PrivKeyPath { get; set; }
    private ECDsa? _privKeyECDsa;
    public ECDsa? PrivKeyECDsa
    {
        get
        {
            if (_privKeyECDsa is not null)
                return _privKeyECDsa;

            if (!string.IsNullOrWhiteSpace(PrivKeyPath))
            {
                if (File.Exists(PrivKeyPath))
                {
                    try
                    {
                        var pem = File.ReadAllText(PrivKeyPath);
                        _privKeyECDsa = ECDsa.Create();
                        _privKeyECDsa.ImportFromPem(pem);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[System] {e.GetType().Name}. Failed to import private key. {e.Message}");

                        _privKeyECDsa?.Dispose();
                        _privKeyECDsa = null;
                    }
                }
                else
                {
                    Console.WriteLine($"[System] Private Key file not found at path: {PrivKeyPath}");
                }
            }

            if (_privKeyECDsa is null)
            {
                var cert = Certificate;
                if (cert.HasPrivateKey)
                    _privKeyECDsa = cert.GetECDsaPrivateKey();
            }

            return _privKeyECDsa;
        }
    }

    public int MaxClients { get; set; } = 1024;
    public int MaxClientsPerRemoteNetwork { get; set; } = 8;

    public int MaxInactivitySeconds { get; set; } = 90;
}
