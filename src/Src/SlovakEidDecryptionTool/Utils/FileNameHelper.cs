using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.IO;

namespace SlovakEidDecryptionTool.Utils
{
    internal static class FileNameHelper
    {
        private const string BadFileNameText = "Invalid file name.";

        public static void CheckFileName(string fileName, string name)
        {
            if (string.Equals(string.Empty, fileName, StringComparison.Ordinal))
            {
                return;
            }

            if (fileName.Length > 254 ||
                fileName.IndexOf('/') != -1 ||
                fileName.IndexOf('\\') != -1 ||
                fileName.IndexOfAny(Path.GetInvalidFileNameChars()) != -1 ||
                Regex.IsMatch(fileName, @"^(PRN|AUX|NUL|CON|COM[1-9]|LPT[1-9]|(\.+)$)|(^\..*$)|(^[\. ]+$)", RegexOptions.IgnoreCase))
            {
                throw new SlovakEidDecryptionException(string.Format(BadFileNameText, name));
            }
        }
    }
}
