using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using SlovakEidDecryptionTool.Tests.Utils;
using SoftHSMv2ForTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Tests
{
    [TestClass]
    public class EidTests
    {
        public const string EpTokenName = "SIG_EP";
        public const string ZepTokenName = "SIG_ZEP";
        public const string TokenSoPin = "123456";
        public const string TokenUserPin = "12345678";

        private const string P12Password = "123456";

        private static SoftHsmContext softHsmContext = null;

        public static string Pkcs11LibPath
        {
            get => softHsmContext.Pkcs11LibPath;
        }

        [ClassInitialize]
        public static void ClassInitialize(TestContext context)
        {
            softHsmContext = SoftHsmInitializer.Init(opt =>
            {
                opt.DeployFolder = Path.Combine(Path.GetTempPath(), $"SoftHSMv2-{Guid.NewGuid():D}");

                opt.LabelName = EpTokenName;
                opt.Pin = TokenUserPin;
                opt.SoPin = TokenSoPin;
            });

            ImportCertificate();
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            softHsmContext?.Dispose();
        }

        private static void ImportCertificate()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Pkcs11LibPath, AppType.SingleThreaded))
            {
                Slot slot = pkcs11.GetSlotList(SlotsType.WithOrWithoutTokenPresent).Single(t => t.GetTokenInfo().Label == EpTokenName);
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, TokenUserPin);

                    using (P12RsaImporter importer = new P12RsaImporter("./Data/EncryptedCert.p12", P12Password))
                    {
                        importer.ImportTo(session,
                            Guid.NewGuid().ToString("D"),
                            Guid.NewGuid().ToString("D"),
                        P12ImportedParts.PrivateKey | P12ImportedParts.Certificate);
                    }
                }
            }
        }

        [TestMethod]
        public async Task ExtractPublicCertificate()
        {
            using EidRsaCryptoAccessor eidRsaCryptoAccessor = new EidRsaCryptoAccessor(Pkcs11LibPath, new MockPinProvider(TokenUserPin), EpTokenName);

            System.Security.Cryptography.X509Certificates.X509Certificate2 certificate = await eidRsaCryptoAccessor.ExtractPublicCertificate();

            Assert.IsNotNull(certificate);
            Assert.IsNotNull(certificate.ToString());
        }

        [TestMethod]
        public async Task WriteReadData()
        {
            const string fileName = "hello.txt";
            Random rand = new Random(156);
            byte[] data = new byte[1024 * 156];
            rand.NextBytes(data);

            using EidRsaCryptoAccessor eidRsaCryptoAccessor = new EidRsaCryptoAccessor(Pkcs11LibPath, new MockPinProvider(TokenUserPin), EpTokenName);

            using MemoryStream writeMs = new MemoryStream();
            using (ContainerWriter writer = new ContainerWriter(writeMs, fileName, await eidRsaCryptoAccessor.ExtractPublicCertificate()))
            {
                await writer.Write(data, 0, data.Length);
            }

            using MemoryStream readMs = new MemoryStream(writeMs.ToArray());

            using (ContainerReader reader = new ContainerReader(readMs, eidRsaCryptoAccessor))
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
    }

    internal class MockPinProvider : IBokPinProvider
    {
        private readonly string pin;

        public MockPinProvider(string pin)
        {
            this.pin = pin;
        }

        public Task<byte[]> GetBokPin()
        {
            return Task.FromResult(Encoding.UTF8.GetBytes(this.pin));
        }
    }
}
