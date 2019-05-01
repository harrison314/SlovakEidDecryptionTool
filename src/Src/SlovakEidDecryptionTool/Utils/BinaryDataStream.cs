using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Utils
{
    internal class BinaryDataStream : Stream
    {
        private readonly Stream parentStream;
        private readonly bool canDisposeParentStream;

        public override bool CanRead
        {
            get => this.parentStream.CanRead;
        }

        public override bool CanSeek
        {
            get => this.parentStream.CanSeek;
        }

        public override bool CanWrite
        {
            get => this.parentStream.CanWrite;
        }

        public override long Length
        {
            get => this.parentStream.Length;
        }

        public override long Position
        {
            get => this.parentStream.Position;
            set => this.parentStream.Position = value;
        }

        public BinaryDataStream(Stream parentStream, bool canDisposeParentStream = false)
        {
            if (parentStream == null)
            {
                throw new ArgumentNullException(nameof(parentStream));
            }

            this.parentStream = parentStream;
            this.canDisposeParentStream = canDisposeParentStream;
        }

        public override void Flush()
        {
            this.parentStream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return this.parentStream.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return this.parentStream.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            this.parentStream.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.parentStream.Write(buffer, offset, count);
        }

        protected override void Dispose(bool disposing)
        {
            if (this.canDisposeParentStream)
            {
                base.Dispose(disposing);
            }
        }

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            return this.parentStream.CopyToAsync(destination, bufferSize, cancellationToken);
        }

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            return this.parentStream.FlushAsync(cancellationToken);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return this.parentStream.ReadAsync(buffer, offset, count, cancellationToken);
        }

        public override int ReadByte()
        {
            return this.parentStream.ReadByte();
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return this.parentStream.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override void WriteByte(byte value)
        {
            this.parentStream.WriteByte(value);
        }

        public async Task Write2BitNumber(ushort number)
        {
            byte[] buffer = new byte[2];
            buffer[0] = (byte)(number & 0xFF);
            buffer[1] = (byte)(number >> 8 & 0xFF);

            await this.parentStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
        }

        public async Task<ushort> Read2BitNumber()
        {
            byte[] buffer = new byte[2];
            int readed = await this.parentStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (readed != buffer.Length)
            {
                throw new InvalidDataException("Can not read 4 bit number from stream.");
            }

            ushort value = (ushort)buffer[0];
            value += (ushort)(buffer[1] << 8);

            return value;
        }

        public async Task Write4BitNumber(uint number)
        {
            byte[] buffer = new byte[4];
            buffer[0] = (byte)(number & 0xFF);
            buffer[1] = (byte)(number >> 8 & 0xFF);
            buffer[2] = (byte)(number >> 16 & 0xFF);
            buffer[3] = (byte)(number >> 24 & 0xFF);

            await this.parentStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
        }

        public async Task<uint> Read4BitNumber()
        {
            byte[] buffer = new byte[4];
            int readed = await this.parentStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (readed != buffer.Length)
            {
                throw new InvalidDataException("Can not read 4 bit number from stream.");
            }

            uint value = 0;
            for (int i = 3; i >= 0; i--)
            {
                value <<= 8;
                value += (uint)buffer[i];
            }

            return value;
        }
        public async Task Write8BitNumber(ulong number)
        {
            byte[] buffer = new byte[8];
            buffer[0] = (byte)(number & 0xFF);
            buffer[1] = (byte)(number >> 8 & 0xFF);
            buffer[2] = (byte)(number >> 16 & 0xFF);
            buffer[3] = (byte)(number >> 24 & 0xFF);
            buffer[4] = (byte)(number >> 32 & 0xFF);
            buffer[5] = (byte)(number >> 40 & 0xFF);
            buffer[6] = (byte)(number >> 48 & 0xFF);
            buffer[7] = (byte)(number >> 56 & 0xFF);

            await this.parentStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
        }

        public async Task<ulong> Read8BitNumber()
        {
            byte[] buffer = new byte[8];
            int readed = await this.parentStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (readed != buffer.Length)
            {
                throw new InvalidDataException("Can not read 8 bit number from stream..");
            }

            ulong value = 0U;
            for (int i = 7; i >= 0; i--)
            {
                value <<= 8;
                value += (ulong)buffer[i];
            }

            return value;
        }

        public async Task WriteConstantString(string str, Encoding encoding)
        {
            byte[] buffer = encoding.GetBytes(str);
            await this.parentStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
        }

        public async Task<string> ReadConstatntString(int lenght, Encoding encoding)
        {
            byte[] buffer = new byte[lenght];
            int readed = await this.parentStream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (readed != buffer.Length)
            {
                throw new InvalidDataException("Can not read string from stream.");
            }

            return encoding.GetString(buffer);
        }
    }
}
