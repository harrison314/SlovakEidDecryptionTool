using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;

namespace SlovakEidDecryptionTool
{
    public class SlovakEidDecryptionException : ApplicationException
    {
        public SlovakEidDecryptionException()
        {
        }

        public SlovakEidDecryptionException(string message) 
            : base(message)
        {
        }

        public SlovakEidDecryptionException(string message, Exception innerException) 
            : base(message, innerException)
        {
        }

        protected SlovakEidDecryptionException(SerializationInfo info, StreamingContext context) 
            : base(info, context)
        {
        }
    }
}
