using Microsoft.VisualStudio.TestTools.UnitTesting;
using SlovakEidDecryptionTool.Utils;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Tests
{
    [TestClass]
    public class BinaryDataStreamTests
    {
        [DataTestMethod]
        [DataRow((ushort)0)]
        [DataRow((ushort)1)]
        [DataRow((ushort)8)]
        [DataRow((ushort)50)]
        [DataRow((ushort)489)]
        [DataRow((ushort)15697)]
        [DataRow((ushort)18546)]
        public async Task WriteRead2ByteNumber(ushort value)
        {
            using MemoryStream ms = new MemoryStream();
            using BinaryDataStream stream = new BinaryDataStream(ms);
            await stream.Write2BitNumber(value);
            await stream.FlushAsync();
            stream.Position = 0;

            ushort readedValue = await stream.Read2BitNumber();
            Assert.AreEqual(value, readedValue);
        }

        [DataTestMethod]
        [DataRow((uint)0)]
        [DataRow((uint)1)]
        [DataRow((uint)50)]
        [DataRow((uint)489)]
        [DataRow((uint)15697)]
        [DataRow((uint)18546)]
        [DataRow((uint)45265478)]
        [DataRow((uint)36975145)]
        public async Task WriteRead4ByteNumber(uint value)
        {
            using MemoryStream ms = new MemoryStream();
            using BinaryDataStream stream = new BinaryDataStream(ms);
            await stream.Write4BitNumber(value);
            await stream.FlushAsync();
            stream.Position = 0;

            uint readedValue = await stream.Read4BitNumber();
            Assert.AreEqual(value, readedValue);

        }

        [DataTestMethod]
        [DataRow((ulong)0)]
        [DataRow((ulong)1)]
        [DataRow((ulong)50)]
        [DataRow((ulong)489)]
        [DataRow((ulong)15697)]
        [DataRow((ulong)18546)]
        [DataRow((ulong)45265478)]
        [DataRow((ulong)36975145)]
        [DataRow((ulong)369745895145)]
        public async Task WriteRead8ByteNumber(ulong value)
        {
            using MemoryStream ms = new MemoryStream();
            using BinaryDataStream stream = new BinaryDataStream(ms);
            await stream.Write8BitNumber(value);
            await stream.FlushAsync();
            stream.Position = 0;

            ulong readedValue = await stream.Read8BitNumber();
            Assert.AreEqual(value, readedValue);
        }

        [TestMethod]
        public async Task WriteConstantString()
        {
            const string text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras a dignissim nunc. Sed nec dapibus ex. Sed a ex non diam ornare scelerisque nec ut lectus. Duis faucibus, lacus nec venenatis placerat, eros nulla consequat ligula, quis interdum eros lacus sit amet purus. Phasellus ac ex id tortor vulputate dignissim. Cras rutrum leo libero, in mattis nulla finibus id. Nunc sed turpis nulla. Sed eget augue vitae enim imperdiet fermentum sed id massa. Fusce vulputate, lacus in interdum venenatis, sapien eros interdum orci, id malesuada ex ligula id nunc. Aenean in dapibus arcu. Vestibulum mollis feugiat justo, bibendum malesuada velit aliquet a. Mauris id venenatis tellus, et condimentum elit.";
            using MemoryStream ms = new MemoryStream();
            using BinaryDataStream stream = new BinaryDataStream(ms);

            await stream.WriteConstantString(text, Encoding.UTF8);
            stream.Position = 0;

            string response = await stream.ReadConstatntString(Encoding.UTF8.GetByteCount(text), Encoding.UTF8);

            Assert.AreEqual(text, response);
        }
    }
}
