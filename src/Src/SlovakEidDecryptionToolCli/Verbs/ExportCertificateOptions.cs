using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionToolCli.Verbs
{
    [Verb("exportCert", HelpText = "Export certificate from Slovak eID.")]
    public class ExportCertificateOptions
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

        [Value(0, MetaName = "certificatePath", Default = null, Required = false, HelpText = "Path to exported certificate file.")]
        public string ExportCertificatePath
        {
            get;
            set;
        }

        public ExportCertificateOptions()
        {

        }
    }
}
