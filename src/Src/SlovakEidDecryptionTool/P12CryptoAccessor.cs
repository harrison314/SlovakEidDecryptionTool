using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public class P12CryptoAccessor : IRsaCryptoAccessor
    {
        private readonly X509Certificate2 p12Certificate;

        public P12CryptoAccessor(byte[] data, string password)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.p12Certificate = new X509Certificate2(data, password);
        }

        public P12CryptoAccessor(string path, string password)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            if (password == null)
            {
                throw new ArgumentNullException(nameof(password));
            }

            this.p12Certificate = new X509Certificate2(path, password);
        }

        public P12CryptoAccessor(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (!certificate.HasPrivateKey)
            {
                throw new ArgumentException("Certificate has not private key.");
            }

            this.p12Certificate = certificate;
        }

        public Task<byte[]> AsymetricDecrypt(string certificateThumbprint, byte[] data, RSAEncryptionPadding padding)
        {
            if (certificateThumbprint == null)
            {
                throw new ArgumentNullException(nameof(certificateThumbprint));
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (!string.Equals(certificateThumbprint, this.p12Certificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"This instance does not contain certificate with thumbprint {certificateThumbprint}.");
            }

            byte[] decrypted = this.p12Certificate.GetRSAPrivateKey().Decrypt(data, padding);
            return Task.FromResult(decrypted);
        }

        public Task<X509Certificate2> ExtractPublicCertificate()
        {
            X509Certificate2 publicCloned = new X509Certificate2(this.p12Certificate.RawData);
            return Task.FromResult(publicCloned);
        }
    }
}
