using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public enum ContainerKeyType :uint
    {
        Rsa2048 = 1U,
        Rsa3072 = 2U,
        Rsa4096 = 3U
    }
}
