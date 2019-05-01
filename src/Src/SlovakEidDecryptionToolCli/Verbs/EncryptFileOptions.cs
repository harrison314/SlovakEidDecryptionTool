using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionToolCli.Verbs
{
    [Verb("encrypt", HelpText = "Encrypt file using X509 certificate.")]
    public class EncryptFileOptions
    {
        [Value(0, MetaName = "certificatePath", Default = null, Required = true, HelpText = "Path to exported certificate file.")]
        public string CertificatePath
        {
            get;
            set;
        }

        [Value(1, MetaName = "fileToEncrypt", Default = null, Required = true, HelpText = "Path to file to encrypt.")]
        public string FileToEncrypt
        {
            get;
            set;
        }

        [Value(2, MetaName = "encryptedFile", Default = null, Required = true, HelpText = "Path to encrypted file.")]
        public string EncryptedFile
        {
            get;
            set;
        }

        [Option('a', "additionalPadding", Default = "50k", HelpText = "Additional output file padding. Eg. 45 is 45B, 50k is 50KB, 2M is2MB.")]
        public string AdditionalPadding
        {
            get;
            set;
        }

        public EncryptFileOptions()
        {

        }

        internal uint ParseAdditionalPadingSize()
        {
            if (this.AdditionalPadding.EndsWith("k", StringComparison.OrdinalIgnoreCase))
            {
                return 1024 * uint.Parse(this.AdditionalPadding.Substring(0, this.AdditionalPadding.Length - 1));
            }

            if (this.AdditionalPadding.EndsWith("m", StringComparison.OrdinalIgnoreCase))
            {
                return 1024 * 1024 * uint.Parse(this.AdditionalPadding.Substring(0, this.AdditionalPadding.Length - 1));
            }

            return uint.Parse(this.AdditionalPadding);
        }
    }
}
