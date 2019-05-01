using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Pkcs;
using System.IO;

namespace SlovakEidDecryptionTool.Tests.Utils
{
    /// <summary>
    /// Helper for generate certificate
    /// </summary>
    /// <remarks>
    /// https://gist.github.com/yutopio/a217a4af63cf6bcf0a530c14c074cf8f
    /// </remarks>
    internal class BouncyCastleCertGenerator
    {
        private static SecureRandom secureRandom = new SecureRandom();
        private X509V3CertificateGenerator certGenerator;

        public X509V3CertificateGenerator Generator
        {
            get => this.certGenerator;
        }

        public BouncyCastleCertGenerator()
        {
            this.certGenerator = new X509V3CertificateGenerator();
        }

        public X509Certificate GenerateRsaCertificate(byte[] subjectPublicKeyInfo, int keySize)
        {
            AsymmetricKeyParameter publicKey = this.ProcessSubjectPublicKeyInfo(subjectPublicKeyInfo);
            this.certGenerator.SetPublicKey(publicKey);

            AsymmetricCipherKeyPair signedKeys = this.GenerateRsaKeyPair(keySize);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                signedKeys.Private);

            X509Certificate cert = this.certGenerator.Generate(signatureFactory);

            return cert;
        }

        public void SetValidity(TimeSpan duration)
        {
            this.Generator.SetNotAfter(DateTime.Now.Date.Add(duration));
            this.Generator.SetNotBefore(DateTime.Now.Date);
        }

        public void SetSubject(string textRepresentation)
        {
            this.Generator.SetSubjectDN(new X509Name(textRepresentation));
            this.Generator.SetIssuerDN(new X509Name(textRepresentation));
        }

        public void SetExtensions(CertCapabitilies certCapabitilies)
        {
            System.Collections.ArrayList certificatePermissions = new System.Collections.ArrayList();

            if (certCapabitilies.HasFlag(CertCapabitilies.ClientAuth))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPClientAuth);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.CodeSigning))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPCodeSigning);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.EmailProtection))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPEmailProtection);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.OcspSigning))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPOcspSigning);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.ServerAuth))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPServerAuth);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.SmartCardLogon))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPSmartCardLogon);
            }

            if (certCapabitilies.HasFlag(CertCapabitilies.TimeStamping))
            {
                certificatePermissions.Add(KeyPurposeID.IdKPTimeStamping);
            }

            this.Generator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(certificatePermissions));

        }

        public void SetSerialNumber(int number)
        {
            this.Generator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(number.ToString(), 10));
        }

        public void SetSerialNumber(string number, int radix = 16)
        {
            this.Generator.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(number, radix));
        }

        public X509Certificate GenerateRsaSelfSignedCertificate(int keySize)
        {
            AsymmetricCipherKeyPair signedKeys = this.GenerateRsaKeyPair(keySize);
            this.certGenerator.SetPublicKey(signedKeys.Public);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                signedKeys.Private);

            X509Certificate cert = this.certGenerator.Generate(signatureFactory);

            return cert;
        }

        public X509Certificate GenerateEcCertificate(byte[] subjectPublicKeyInfo)
        {
            AsymmetricKeyParameter publicKey = this.ProcessSubjectPublicKeyInfo(subjectPublicKeyInfo);
            this.certGenerator.SetPublicKey(publicKey);

            AsymmetricCipherKeyPair signedKeys = this.GenerateEcKeyPair();
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                signedKeys.Private);

            X509Certificate cert = this.certGenerator.Generate(signatureFactory);

            return cert;
        }

        public X509Certificate GenerateEcSelfSignedCertificate()
        {
            AsymmetricCipherKeyPair signedKeys = this.GenerateEcKeyPair();
            this.certGenerator.SetPublicKey(signedKeys.Public);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                X9ObjectIdentifiers.ECDsaWithSha256.ToString(),
                signedKeys.Private);

            X509Certificate cert = this.certGenerator.Generate(signatureFactory);

            return cert;
        }

        public byte[] GenerateRsaSelfSignedP12Certificate(int keySize, string password = "")
        {
            AsymmetricCipherKeyPair signedKeys = this.GenerateRsaKeyPair(keySize);
            this.certGenerator.SetPublicKey(signedKeys.Public);
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(),
                signedKeys.Private);

            X509Certificate cert = this.certGenerator.Generate(signatureFactory);

            Pkcs12Store pkcs12Store = new Pkcs12Store();
            pkcs12Store.SetKeyEntry("MyKey", new AsymmetricKeyEntry(signedKeys.Private), new X509CertificateEntry[]{
                new X509CertificateEntry(cert)
            });

            using (MemoryStream ms = new MemoryStream())
            {
                pkcs12Store.Save(ms, password.ToCharArray(), secureRandom);

                return ms.ToArray();
            }
        }


        private AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            KeyGenerationParameters keygenParam = new KeyGenerationParameters(secureRandom, length);

            RsaKeyPairGenerator keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(keygenParam);

            return keyGenerator.GenerateKeyPair();
        }

        private AsymmetricCipherKeyPair GenerateEcKeyPair(string curveName = "secp256r1")
        {
            X9ECParameters ecParam = SecNamedCurves.GetByName(curveName);
            ECDomainParameters ecDomain = new ECDomainParameters(ecParam.Curve, ecParam.G, ecParam.N);
            ECKeyGenerationParameters keygenParam = new ECKeyGenerationParameters(ecDomain, secureRandom);

            ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
            keyGenerator.Init(keygenParam);

            return keyGenerator.GenerateKeyPair();
        }

        private AsymmetricKeyParameter ProcessSubjectPublicKeyInfo(byte[] subjectPublicKeyInfo)
        {
            Org.BouncyCastle.Asn1.Asn1Object asn1PublicKey = Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(subjectPublicKeyInfo);
            Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo subjectPublicKey = Org.BouncyCastle.Asn1.X509.SubjectPublicKeyInfo.GetInstance(asn1PublicKey);
            AsymmetricKeyParameter publicKey = Org.BouncyCastle.Security.PublicKeyFactory.CreateKey(subjectPublicKey);

            return publicKey;
        }
    }
}
