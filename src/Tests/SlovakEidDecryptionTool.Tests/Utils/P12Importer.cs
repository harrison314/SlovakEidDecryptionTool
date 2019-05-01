using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Tests.Utils
{
    public class P12RsaImporter : IDisposable
    {
        private readonly RsaPrivateCrtKeyParameters rsaPrivateKey;
        private readonly X509Certificate certificate;
        private readonly Stream internalStream;

        public P12RsaImporter(byte[] p12Content, string password)
        {
            if (p12Content == null)
            {
                throw new ArgumentNullException(nameof(p12Content));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.internalStream = new MemoryStream(p12Content);
            (this.rsaPrivateKey, this.certificate) = this.Extract(this.internalStream, password);
        }

        public P12RsaImporter(Stream p12Stream, string password)
        {
            if (p12Stream == null)
            {
                throw new ArgumentNullException(nameof(p12Stream));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.internalStream = null;
            (this.rsaPrivateKey, this.certificate) = this.Extract(p12Stream, password);
        }

        public P12RsaImporter(string fileName, string password)
        {
            if (fileName == null)
            {
                throw new ArgumentNullException(nameof(fileName));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.internalStream = File.OpenRead(fileName);
            (this.rsaPrivateKey, this.certificate) = this.Extract(this.internalStream, password);
        }

        public void ImportTo(Session pkcs11Session, byte[] ckaLabel, byte[] ckaId, P12ImportedParts importParams)
        {
            if (pkcs11Session == null)
            {
                throw new ArgumentNullException(nameof(pkcs11Session));
            }

            if (ckaLabel == null)
            {
                throw new ArgumentNullException(nameof(ckaLabel));
            }

            if (ckaId == null)
            {
                throw new ArgumentNullException(nameof(ckaId));
            }

            if (importParams.HasFlag(P12ImportedParts.PrivateKey))
            {
                this.ImportPrivateKey(ckaLabel, ckaId, pkcs11Session);
            }

            if (importParams.HasFlag(P12ImportedParts.PublicKey))
            {
                this.ImportPublicKey(ckaLabel, ckaId, pkcs11Session);
            }

            if (importParams.HasFlag(P12ImportedParts.Certificate))
            {
                this.ImportCertificate(ckaLabel, ckaId, pkcs11Session);
            }
        }

        public void ImportTo(Session pkcs11Session, string ckaLabel, string ckaId, P12ImportedParts importParams)
        {
            if (pkcs11Session == null)
            {
                throw new ArgumentNullException(nameof(pkcs11Session));
            }

            if (ckaLabel == null)
            {
                throw new ArgumentNullException(nameof(ckaLabel));
            }

            if (ckaId == null)
            {
                throw new ArgumentNullException(nameof(ckaId));
            }

            this.ImportTo(pkcs11Session,
                Encoding.UTF8.GetBytes(ckaLabel),
                Encoding.UTF8.GetBytes(ckaId),
               importParams);
        }

        public void Dispose()
        {
            this.Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.internalStream?.Dispose();
            }
        }

        private (RsaPrivateCrtKeyParameters rsaPrivateKey, X509Certificate certificate) Extract(Stream stream, string password)
        {
            Org.BouncyCastle.Pkcs.Pkcs12Store p12Store = new Org.BouncyCastle.Pkcs.Pkcs12Store(stream, password.ToCharArray());
            string keyEntryAlias = p12Store.Aliases.Cast<string>().FirstOrDefault(t => p12Store.IsKeyEntry(t));

            Org.BouncyCastle.Pkcs.X509CertificateEntry x509CertEntry = p12Store.GetCertificate(keyEntryAlias);

            Org.BouncyCastle.Pkcs.AsymmetricKeyEntry keyEntry = p12Store.GetKey(keyEntryAlias);
            return (keyEntry.Key as RsaPrivateCrtKeyParameters, x509CertEntry.Certificate);
        }

        private void ImportCertificate(byte[] ckaLabel, byte[] ckaId, Session pkcs11Session)
        {
            List<ObjectAttribute> certificateAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
                new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                new ObjectAttribute(CKA.CKA_ID, ckaId),
                new ObjectAttribute(CKA.CKA_LABEL, ckaLabel),
                new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                new ObjectAttribute(CKA.CKA_TRUSTED, false),
                new ObjectAttribute(CKA.CKA_SUBJECT, this.certificate.SubjectDN.GetDerEncoded()),
                new ObjectAttribute(CKA.CKA_ISSUER, this.certificate.IssuerDN.GetDerEncoded()),
                new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, new DerInteger(this.certificate.SerialNumber).GetDerEncoded()),
                new ObjectAttribute(CKA.CKA_VALUE, this.certificate.GetEncoded())
            };

            pkcs11Session.CreateObject(certificateAttributes);
        }

        private void ImportPublicKey(byte[] ckaLabel, byte[] ckaId, Session pkcs11Session)
        {

            List<ObjectAttribute> publicKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
                new ObjectAttribute(CKA.CKA_ENCRYPT, true),
                new ObjectAttribute(CKA.CKA_VERIFY, true),
                new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true),
                new ObjectAttribute(CKA.CKA_WRAP, true),
                new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                new ObjectAttribute(CKA.CKA_ID,ckaId),
                new ObjectAttribute(CKA.CKA_LABEL, ckaLabel),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                new ObjectAttribute(CKA.CKA_MODULUS, this.rsaPrivateKey.Modulus.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, this.rsaPrivateKey.Exponent.ToByteArrayUnsigned())
            };

            pkcs11Session.CreateObject(publicKeyAttributes);
        }

        private void ImportPrivateKey(byte[] ckaLabel, byte[] ckaId, Session pkcs11Session)
        {
            List<ObjectAttribute> privateKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                new ObjectAttribute(CKA.CKA_SIGN, true),
                new ObjectAttribute(CKA.CKA_SIGN_RECOVER, false),
                new ObjectAttribute(CKA.CKA_DECRYPT, true),
                new ObjectAttribute(CKA.CKA_UNWRAP, true),
                new ObjectAttribute(CKA.CKA_ID, ckaId),
                new ObjectAttribute(CKA.CKA_LABEL, ckaLabel),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                new ObjectAttribute(CKA.CKA_MODULUS, this.rsaPrivateKey.Modulus.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, this.rsaPrivateKey.PublicExponent.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, this.rsaPrivateKey.Exponent.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_PRIME_1, this.rsaPrivateKey.P.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_PRIME_2, this.rsaPrivateKey.Q.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_EXPONENT_1, this.rsaPrivateKey.DP.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_EXPONENT_2, this.rsaPrivateKey.DQ.ToByteArrayUnsigned()),
                new ObjectAttribute(CKA.CKA_COEFFICIENT, this.rsaPrivateKey.QInv.ToByteArrayUnsigned())
            };

            pkcs11Session.CreateObject(privateKeyAttributes);
        }
    }
}
