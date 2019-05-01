using SlovakEidDecryptionTool.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public class ContainerReader : IDisposable
    {
        private readonly Stream readerStream;
        private readonly IRsaCryptoAccessor cryptoAccessor;
        private string? fileName;
        private CryptoStream? cryptoStream;
        private readonly AesManaged aes;
        private ICryptoTransform? aesDecryptor;

        public ContainerReader(Stream readStream, IRsaCryptoAccessor cryptoAccessor)
        {
            if (readStream == null)
            {
                throw new ArgumentNullException(nameof(readStream));
            }

            if (cryptoAccessor == null)
            {
                throw new ArgumentNullException(nameof(cryptoAccessor));
            }

            this.readerStream = readStream;
            this.cryptoAccessor = cryptoAccessor;
            this.fileName = null;
            this.aes = new AesManaged();

            this.aes.Mode = CipherMode.CBC;
            this.aes.Padding = PaddingMode.PKCS7;
            this.aes.KeySize = 256;
            this.aes.BlockSize = 128;
        }

        public async Task<string> ReadFileName()
        {
            if (this.fileName != null)
            {
                return this.fileName;
            }

            ContainerHeader header = await ContainerHeader.ReadFromStream(this.readerStream);
            byte[]? aesKey = null;
            try
            {
                aesKey = await this.cryptoAccessor.AsymetricDecrypt(header.CertificateThumbprint, header.EncryptedKey, RSAEncryptionPadding.Pkcs1);  //RSA Padding
                this.aesDecryptor = this.aes.CreateDecryptor(aesKey, header.InitializeVector);
                this.cryptoStream = new CryptoStream(this.readerStream, this.aesDecryptor, CryptoStreamMode.Read);
               
                using (BinaryDataStream bds = new BinaryDataStream(this.cryptoStream, false))
                {
                    //TODO: Optimalization
                    for (uint i = 0; i < 16; i++)
                    {
                        bds.ReadByte();
                    }

                    uint randomDataSize = await bds.Read4BitNumber();
                    uint stringLen = await bds.Read4BitNumber();

                    //TODO: Optimalization
                    for (uint i = 0; i < randomDataSize; i++)
                    {
                        bds.ReadByte();
                    }

                    string fileName = await bds.ReadConstatntString((int)stringLen, Encoding.UTF8);
                    FileNameHelper.CheckFileName(fileName, nameof(fileName));
                    this.fileName = fileName;

                    return fileName;
                }
            }
            finally
            {
                if (aesKey != null)
                {
                    for (int i = 0; i < aesKey.Length; i++)
                    {
                        aesKey[i] = 0x00;
                        aesKey[i] = 0xFF;
                    }
                }
            }
        }

        public async Task<Stream> GetContentStream()
        {
            await this.ReadFileName();
#pragma warning disable CS8603 // Possible null reference return.
            return this.cryptoStream;
#pragma warning restore CS8603 // Possible null reference return.
        }

        public void Dispose()
        {
            this.Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.aes?.Dispose();
                this.aesDecryptor?.Dispose();
                this.cryptoStream?.Dispose();
            }
        }
    }
}
