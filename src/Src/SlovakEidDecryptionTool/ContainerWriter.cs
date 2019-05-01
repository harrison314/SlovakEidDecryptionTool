using SlovakEidDecryptionTool.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public class ContainerWriter : IDisposable
    {
        private readonly Stream writeStream;
        private readonly string fileName;
        private readonly AesManaged aes;
        private readonly ICryptoTransform encryptor;
        private readonly Random randomSource;
        private bool headerWrited;
        private readonly ContainerHeader header;
        private CryptoStream? cryptoStream;

        public uint AdditionalPadingSize
        {
            get;
            set;
        }

        public ContainerWriter(Stream writeStream, string fileName, X509Certificate2 certificate)
        {
            this.writeStream = writeStream ?? throw new ArgumentNullException(nameof(writeStream));
            this.fileName = fileName ?? throw new ArgumentNullException(nameof(writeStream));
            FileNameHelper.CheckFileName(fileName, nameof(fileName));

            this.aes = new AesManaged();
            this.aes.Mode = CipherMode.CBC;
            this.aes.Padding = PaddingMode.PKCS7;
            this.aes.KeySize = 256;
            this.aes.BlockSize = 128;

            this.randomSource = new Random(Guid.NewGuid().GetHashCode());

            this.aes.GenerateKey();
            this.aes.GenerateIV();

            this.header = new ContainerHeader();
            this.header.CertificateThumbprint = certificate.Thumbprint;
            this.header.EncryptedDataSize = 0L;
            this.header.KeyType = this.GetKeyType(certificate.GetRSAPublicKey());
            this.header.EncryptedKey = certificate.GetRSAPublicKey().Encrypt(this.aes.Key, RSAEncryptionPadding.Pkcs1); //RSA Padding
            this.header.InitializeVector = this.aes.IV;

            this.encryptor = this.aes.CreateEncryptor();
            this.headerWrited = false;
            this.AdditionalPadingSize = (uint)this.randomSource.Next(512, 2048);
        }

        public ContainerWriter(Stream writeStream, X509Certificate2 certificate)
            : this(writeStream, string.Empty, certificate)
        {

        }

        public async Task Write(byte[] data, int offset, int length)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            await this.EnshureInitialize();
            await this.cryptoStream!.WriteAsync(data, offset, length).ConfigureAwait(false);
        }

        public async Task Write(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            await this.EnshureInitialize();
            await stream.CopyToAsync(this.cryptoStream);
        }

        public void Dispose()
        {
            this.Dispose(true);
        }

        private async Task EnshureInitialize()
        {
            if (!this.headerWrited)
            {
                await this.header.WriteToStream(this.writeStream);
                this.headerWrited = true;
                this.cryptoStream = new CryptoStream(this.writeStream, this.encryptor, CryptoStreamMode.Write);

                using (BinaryDataStream bds = new BinaryDataStream(this.cryptoStream, false))
                {
                    await this.WriteRandomBytes(bds, 16).ConfigureAwait(false);
                    await bds.Write4BitNumber(this.AdditionalPadingSize).ConfigureAwait(false);
                    await bds.Write4BitNumber((uint)Encoding.UTF8.GetByteCount(this.fileName)).ConfigureAwait(false);
                    await this.WriteRandomBytes(bds, this.AdditionalPadingSize).ConfigureAwait(false);

                    await bds.WriteConstantString(this.fileName, Encoding.UTF8).ConfigureAwait(false);
                }
            }
        }

        private async Task WriteRandomBytes(BinaryDataStream bds, long count)
        {
            byte[] buffer = new byte[2048];
            while (count > 0)
            {
                this.randomSource.NextBytes(buffer);
                int writeBytes = (count > buffer.Length) ? buffer.Length : (int)count;
                await bds.WriteAsync(buffer, 0, writeBytes).ConfigureAwait(false);
                count -= writeBytes;
            }
        }

        private ContainerKeyType GetKeyType(RSA rsa)
        {
            return rsa.KeySize switch
            {
                2048 => ContainerKeyType.Rsa2048,
                3072 => ContainerKeyType.Rsa3072,
                4096 => ContainerKeyType.Rsa4096,
                _ => throw new NotSupportedException("Key size is not supported.")
            };
        }

        protected void Dispose(bool disosing)
        {
            if (disosing)
            {
                if (this.headerWrited)
                {
                    this.cryptoStream!.Flush();
                    this.cryptoStream!.Dispose();
                }

                this.encryptor.Dispose();
                this.aes.Dispose();
            }
        }
    }
}
