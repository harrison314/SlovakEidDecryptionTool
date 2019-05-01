using SlovakEidDecryptionTool.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public class ContainerHeader
    {
        public const string HeaderPrefix = "SkEidDT_";
        public const ushort DefaultVersion = 1;
        public const long ContainerHeaderSize = 45;
        public ushort Version
        {
            get;
            protected set;
        }

        public uint Reserved
        {
            get;
            protected set;
        }

        public ulong EncryptedDataSize
        {
            get;
            protected internal set;
        }

        public string CertificateThumbprint
        {
            get;
            protected internal set;
        }

        public ContainerKeyType KeyType
        {
            get;
            protected internal set;
        }

        public byte[] EncryptedKey
        {
            get;
            protected internal set;
        }

        public byte[] InitializeVector
        {
            get;
            protected internal set;
        }

        internal ContainerHeader()
        {
            this.Version = DefaultVersion;
            this.Reserved = 0U;
            this.CertificateThumbprint = string.Empty;
        }

        public static async Task<ContainerHeader> ReadFromStream(Stream stream)
        {
            using (BinaryDataStream dataStream = new BinaryDataStream(stream, false))
            {
                await CheckPrefix(dataStream);
                ContainerHeader header = new ContainerHeader();
                header.Version = await dataStream.Read2BitNumber();
                if (header.Version != DefaultVersion)
                {
                    throw new InvalidOperationException($"Encryption file version {header.Version} is not supported.");
                }

                header.Reserved = await dataStream.Read4BitNumber();
                header.KeyType = (ContainerKeyType)await dataStream.Read4BitNumber();

                int encryptedKeySize = header.KeyType switch
                {
                    ContainerKeyType.Rsa2048 => 256,
                    ContainerKeyType.Rsa3072 => 384,
                    ContainerKeyType.Rsa4096 => 512,
                    _ => throw new NotSupportedException($"Not support key type {header.KeyType}")
                };

                header.EncryptedDataSize = await dataStream.Read8BitNumber();
                header.CertificateThumbprint = await dataStream.ReadConstatntString(40, Encoding.ASCII);
                header.EncryptedKey = new byte[encryptedKeySize];
                header.InitializeVector = new byte[16];

                await dataStream.ReadAsync(header.EncryptedKey, 0, header.EncryptedKey.Length);
                await dataStream.ReadAsync(header.InitializeVector, 0, header.InitializeVector.Length);

                return header;
            }
        }

        public async Task WriteToStream(Stream stream)
        {
            using (BinaryDataStream dataStream = new BinaryDataStream(stream, false))
            {
                await dataStream.WriteConstantString(HeaderPrefix, Encoding.ASCII);
                await dataStream.Write2BitNumber(this.Version);
                await dataStream.Write4BitNumber(0);
                await dataStream.Write4BitNumber((uint)this.KeyType);
                await dataStream.Write8BitNumber(this.EncryptedDataSize);
                await dataStream.WriteConstantString(this.CertificateThumbprint, Encoding.ASCII);
                await dataStream.WriteAsync(this.EncryptedKey, 0, this.EncryptedKey.Length);
                await dataStream.WriteAsync(this.InitializeVector, 0, this.InitializeVector.Length);

                await dataStream.FlushAsync();
            }
        }

        private static async Task CheckPrefix(BinaryDataStream dataStream)
        {
            byte[] buffer = new byte[HeaderPrefix.Length];
            int readed = await dataStream.ReadAsync(buffer, 0, buffer.Length);

            if (readed != buffer.Length || !string.Equals(HeaderPrefix, Encoding.ASCII.GetString(buffer), StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Can not find encryption file header.");
            }
        }
    }
}
