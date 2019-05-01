using SlovakEidDecryptionTool;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionToolCli
{
    public class EidBokPinProvider : IBokPinProvider
    {
        public EidBokPinProvider()
        {

        }

        public Task<byte[]> GetBokPin()
        {
            return Task.FromResult<byte[]>(null);
        }
    }
}
