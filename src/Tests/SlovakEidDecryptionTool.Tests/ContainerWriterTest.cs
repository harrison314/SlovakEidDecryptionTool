using Microsoft.VisualStudio.TestTools.UnitTesting;
using SlovakEidDecryptionTool.Tests.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Tests
{
    [TestClass]
    public class ContainerWriterTest
    {
        [TestMethod]
        public async Task WriteReadData()
        {
            const string fileName = "hello.txt";
            Random rand = new Random(156);
            byte[] data = new byte[1024 * 156];
            rand.NextBytes(data);

            IRsaCryptoAccessor p12CryptoAccessor = this.CreateAccesor();

            using MemoryStream writeMs = new MemoryStream();
            using (ContainerWriter writer = new ContainerWriter(writeMs, fileName, await p12CryptoAccessor.ExtractPublicCertificate()))
            {
                await writer.Write(data, 0, data.Length);
            }

            using MemoryStream readMs = new MemoryStream(writeMs.ToArray());

            using (ContainerReader reader = new ContainerReader(readMs, p12CryptoAccessor))
            {
                string decodedFileName = await reader.ReadFileName();
                Assert.AreEqual(fileName, decodedFileName, "Decoded file name");
                using Stream contentStream = await reader.GetContentStream();
                using MemoryStream buffer = new MemoryStream(data.Length + 10);
                await contentStream.CopyToAsync(buffer);

                byte[] decryptedData = buffer.ToArray();

                Assert.AreEqual(data.Length, decryptedData.Length);
                CollectionAssert.AreEquivalent(data, decryptedData);
            }
        }

        private IRsaCryptoAccessor CreateAccesor()
        {
            BouncyCastleCertGenerator generator = new BouncyCastleCertGenerator();
            generator.SetExtensions(CertCapabitilies.All);
            generator.SetSerialNumber(55);
            generator.SetSubject("SERIALNUMBER=0000000000569, C=SK, CN=Janko Mrkvicka");
            generator.SetValidity(TimeSpan.FromDays(25 * 256));

           byte[] certificate = generator.GenerateRsaSelfSignedP12Certificate(3072+1024, "abc");

            return new P12CryptoAccessor(certificate, "abc");
        }
    }
}
