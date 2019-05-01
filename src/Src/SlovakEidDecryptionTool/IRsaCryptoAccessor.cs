using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public interface IRsaCryptoAccessor
    {
        Task<byte[]> AsymetricDecrypt(string certificateThumbprint, byte[] data, RSAEncryptionPadding padding);

        Task<X509Certificate2> ExtractPublicCertificate();
    }
}
