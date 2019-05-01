using System;

namespace SlovakEidDecryptionTool.Tests.Utils
{
    [Flags]
    public enum P12ImportedParts
    {
        PrivateKey = 1,
        PublicKey = 2,
        Certificate = 4,
        All = PrivateKey | PublicKey | Certificate
    }
}
