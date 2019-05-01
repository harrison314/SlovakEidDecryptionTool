using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public interface IBokPinProvider
    {
        Task<byte[]> GetBokPin();
    }
}
