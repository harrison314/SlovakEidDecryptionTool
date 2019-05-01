using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionToolCli.Verbs
{
    [Verb("decrypt", HelpText = "Decrypt file using eID.")]
    public class DecryptFileOptions
    {
        [Option('l', "pkcs11Lib", Default = null, HelpText = "Full path to PKCS#11 library.")]
        public string LibPath
        {
            get;
            set;
        }

        [Option('c', "useConsolePin", Default = null, HelpText = "Use this console application to set BOK PIN.")]
        public bool UseConsolePin
        {
            get;
            set;
        }

        [Value(0, MetaName = "encryptedFile", Default = null, Required = true, HelpText = "Path to encrypted file.")]
        public string EncryptedFile
        {
            get;
            set;
        }

        public DecryptFileOptions()
        {

        }
    }
}
