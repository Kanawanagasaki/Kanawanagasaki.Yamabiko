namespace Kanawanagasaki.Yamabiko.Dtls.Helpers;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

public static class CertificateHelper
{
    public static bool ValidateCertificatesForDomain(X509Certificate2[] certificates, string domain, TimeSpan urlRetrievalTimeout = default)
    {
        if (certificates.Length == 0)
            return false;
        if (string.IsNullOrWhiteSpace(domain))
            return false;

        if (urlRetrievalTimeout == default)
            urlRetrievalTimeout = TimeSpan.FromSeconds(5);

        var now = DateTime.UtcNow;

        foreach (var cert in certificates)
        {
            try
            {
                if (now < cert.NotBefore || cert.NotAfter < now)
                    continue;

                if (!MatchesDomain(cert, domain))
                    continue;

                if (IsCertificateCA(cert))
                    continue;

                if (!HasServerAuthEku(cert))
                    continue;

                using var chain = new X509Chain();

                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.UrlRetrievalTimeout = urlRetrievalTimeout;

                foreach (var extra in certificates)
                {
                    if (!string.Equals(extra.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase))
                        chain.ChainPolicy.ExtraStore.Add(extra);
                }

                var built = chain.Build(cert);

                if (!built)
                    continue;

                if (chain.ChainStatus.Any(p => p.Status is not X509ChainStatusFlags.NoError))
                    continue;

                return true;
            }
            catch { }
        }

        return false;
    }

    public static bool MatchesDomain(X509Certificate2 cert, string domain)
    {
        var dnsNames = GetSubjectAlternativeNames(cert);
        if (0 < dnsNames.Count)
            return dnsNames.Any(n => MatchHostnameToPattern(domain, n));

        var cn = cert.GetNameInfo(X509NameType.DnsName, false);
        if (string.IsNullOrEmpty(cn))
            cn = cert.GetNameInfo(X509NameType.SimpleName, false);

        return !string.IsNullOrEmpty(cn) && MatchHostnameToPattern(domain, cn);
    }

    public static List<string> GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        var list = new List<string>();

        var sanExt = cert.Extensions.Cast<System.Security.Cryptography.X509Certificates.X509Extension>().FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        if (sanExt is null)
            return list;

        try
        {
            var reader = new AsnReader(sanExt.RawData, AsnEncodingRules.DER);
            var seq = reader.ReadSequence();
            while (seq.HasData)
            {
                var tag = seq.PeekTag();
                if (tag.TagClass is TagClass.ContextSpecific && tag.TagValue == 2)
                {
                    var dns = seq.ReadCharacterString(UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2));
                    list.Add(dns);
                }
                else
                {
                    seq.ReadEncodedValue();
                }
            }
        }
        catch { }

        return list;
    }

    public static bool MatchHostnameToPattern(string hostname, string pattern)
    {
        if (string.Equals(hostname, pattern, StringComparison.OrdinalIgnoreCase))
            return true;

        if (pattern.StartsWith("*."))
        {
            var remainder = pattern.Substring(2);

            if (hostname.Length <= remainder.Length)
                return false;
            if (!hostname.EndsWith(remainder, StringComparison.OrdinalIgnoreCase))
                return false;

            int hostnameLabels = hostname.Split('.').Length;
            int remainderLabels = remainder.Split('.').Length;
            return hostnameLabels == remainderLabels + 1;
        }
        return false;
    }

    public static bool IsCertificateCA(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.19" && ext is X509BasicConstraintsExtension bc)
                return bc.CertificateAuthority;
        }
        return false;
    }

    public static bool HasServerAuthEku(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == "2.5.29.37" && ext is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var oid in eku.EnhancedKeyUsages)
                    if (oid.Value == "1.3.6.1.5.5.7.3.1")
                        return true;

                return false;
            }
        }

        return false;
    }

    public static X509Certificate2 GenerateSelfSignedCertificate(string domain, int keyStrength = 2048, int validityDays = 365)
    {
        var keyGen = new RsaKeyPairGenerator();
        keyGen.Init(new KeyGenerationParameters(new SecureRandom(), keyStrength));
        var keyPair = keyGen.GenerateKeyPair();

        var certGen = new X509V3CertificateGenerator();

        var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), new SecureRandom());
        certGen.SetSerialNumber(serialNumber);

        var subjectDn = new X509Name($"CN={domain}");
        certGen.SetIssuerDN(subjectDn);
        certGen.SetSubjectDN(subjectDn);

        var notBefore = DateTime.UtcNow.AddMinutes(-5);
        var notAfter = notBefore.AddDays(validityDays);
        certGen.SetNotBefore(notBefore);
        certGen.SetNotAfter(notAfter);

        certGen.SetPublicKey(keyPair.Public);

        var subjectKeyId = X509ExtensionUtilities.CreateSubjectKeyIdentifier(keyPair.Public);
        certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyId);

        var authorityKeyIdentifier = X509ExtensionUtilities.CreateAuthorityKeyIdentifier(keyPair.Public);
        certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, authorityKeyIdentifier);

        certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));

        var eku = new ExtendedKeyUsage([KeyPurposeID.id_kp_serverAuth, KeyPurposeID.id_kp_clientAuth]);
        certGen.AddExtension(X509Extensions.ExtendedKeyUsage, false, eku);

        var san = new GeneralNames(new GeneralName(GeneralName.DnsName, domain));
        certGen.AddExtension(X509Extensions.SubjectAlternativeName, false, san);

        var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private, new SecureRandom());

        var bcCert = certGen.Generate(signatureFactory);

        var store = new Pkcs12StoreBuilder().Build();

        var certEntry = new X509CertificateEntry(bcCert);
        store.SetCertificateEntry(domain, certEntry);
        store.SetKeyEntry(domain, new AsymmetricKeyEntry(keyPair.Private), [certEntry]);

        using var ms = new MemoryStream();
        store.Save(ms, string.Empty.ToCharArray(), new SecureRandom());
        var pfxBytes = ms.ToArray();

        return X509CertificateLoader.LoadPkcs12(pfxBytes, string.Empty, X509KeyStorageFlags.Exportable);
    }
}
