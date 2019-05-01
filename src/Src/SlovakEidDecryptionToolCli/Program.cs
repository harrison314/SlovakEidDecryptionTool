using CommandLine;
using SlovakEidDecryptionTool;
using SlovakEidDecryptionToolCli.Verbs;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace SlovakEidDecryptionToolCli
{
    public class Program
    {
        public static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<ExportCertificateOptions, EncryptFileOptions, DecryptFileOptions>(args)
               .MapResult(
                    (ExportCertificateOptions opts) => ExportCertificate(opts),
                    (EncryptFileOptions opts) => EncryptFile(opts),
                    (DecryptFileOptions opts) => DecryptFile(opts),
                    _ => 1);
        }

        private static int ExportCertificate(ExportCertificateOptions opts)
        {
            string pkcs11LibPath = opts.LibPath ?? FindEidLibrary();
            IBokPinProvider pinProvider = CreatePinpProvider(opts.UseConsolePin);
            using EidRsaCryptoAccessor eidRsaCryptoAccessor = new EidRsaCryptoAccessor(pkcs11LibPath, pinProvider);

            X509Certificate2 certificate = eidRsaCryptoAccessor.ExtractPublicCertificate().GetAwaiter().GetResult();

            string savePath = opts.ExportCertificatePath;
            if (string.IsNullOrEmpty(savePath))
            {
                savePath = string.Concat(certificate.Thumbprint, ".cer");
            }

            File.WriteAllBytes(savePath, certificate.RawData);
            return 0;
        }

        private static int EncryptFile(EncryptFileOptions opts)
        {
            string fileName = Path.GetFileName(opts.FileToEncrypt);
            X509Certificate2 certificate = new X509Certificate2(opts.CertificatePath);
            using FileStream outputFiletream = new FileStream(opts.EncryptedFile, FileMode.Create, FileAccess.ReadWrite);
            using FileStream inputFiletream = new FileStream(opts.FileToEncrypt, FileMode.Open, FileAccess.Read);

            using ContainerWriter writer = new ContainerWriter(outputFiletream, fileName, certificate);
            writer.AdditionalPadingSize = opts.ParseAdditionalPadingSize();

            writer.Write(inputFiletream).GetAwaiter().GetResult();

            return 0;
        }

        private static int DecryptFile(DecryptFileOptions opts)
        {
            string pkcs11LibPath = opts.LibPath ?? FindEidLibrary();
            IBokPinProvider pinProvider = CreatePinpProvider(opts.UseConsolePin);
            using EidRsaCryptoAccessor eidRsaCryptoAccessor = new EidRsaCryptoAccessor(pkcs11LibPath, pinProvider);

            using FileStream inputFiletream = new FileStream(opts.EncryptedFile, FileMode.Open, FileAccess.Read);

            using ContainerReader reader = new ContainerReader(inputFiletream, eidRsaCryptoAccessor);

            string fileName = reader.ReadFileName().GetAwaiter().GetResult();
            string outputFilePath = Path.Combine(Path.GetDirectoryName(opts.EncryptedFile), fileName);

            using FileStream outputFiletream = new FileStream(outputFilePath, FileMode.Create, FileAccess.ReadWrite);

            using Stream contentSrream = reader.GetContentStream().GetAwaiter().GetResult();
            contentSrream.CopyTo(outputFiletream);

            return 0;
        }

        private static string FindEidLibrary()
        {
            string[] paths = new string[]
            {
                $@"C:\Program Files (x86)\eID klient\pkcs11_{(IntPtr.Size == 4 ? "x86" : "x64")}.dll",
                $@"C:\Program Files\eID klient\pkcs11_{(IntPtr.Size == 4 ? "x86" : "x64")}.dll",

                $@"C:/Program Files/EAC MW klient/pkcs11_{(IntPtr.Size == 4 ? "x86" : "x64")}.dll",
                $@"C:/Program Files (x86)/EAC MW klient/pkcs11_{(IntPtr.Size == 4 ? "x86" : "x64")}.dll",

                $@"/usr/lib/eidklient/libpkcs11_sig_{(IntPtr.Size == 4 ? "x86" : "x64")}.so"
                // /Applications/eIDklient.app/Contents/Pkcs11/libPkcs11.dylib
            };

            foreach (string potentialPath in paths)
            {
                try
                {
                    if (Path.IsPathFullyQualified(potentialPath) && File.Exists(potentialPath))
                    {
                        return potentialPath;
                    }
                }
                catch (Exception ex)
                {
                    // Ignore exception
                    System.Diagnostics.Trace.WriteLine(ex.ToString());
                }
            }

            throw new IOException("Not found PKCS#11 library.");
        }

        private static IBokPinProvider CreatePinpProvider(bool useConsole)
        {
            if (useConsole)
            {
                return new ConsolePinBokProvider();
            }
            else
            {
                return new EidBokPinProvider();
            }
        }
    }
}
