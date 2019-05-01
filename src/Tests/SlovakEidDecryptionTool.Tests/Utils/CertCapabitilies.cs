using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool.Tests.Utils
{
    [Flags]
    internal enum CertCapabitilies
    {
        CodeSigning = 1,
        ServerAuth = 2,
        TimeStamping = 4,
        OcspSigning = 8,
        ClientAuth = 16,
        EmailProtection = 32,
        SmartCardLogon = 64,
        All = CodeSigning | ServerAuth | TimeStamping | OcspSigning | ClientAuth | EmailProtection | SmartCardLogon,
        Default = CodeSigning | ServerAuth | ClientAuth
    }
}
