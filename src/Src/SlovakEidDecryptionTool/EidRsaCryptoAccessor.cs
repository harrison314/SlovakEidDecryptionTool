using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace SlovakEidDecryptionTool
{
    public class EidRsaCryptoAccessor : IRsaCryptoAccessor, IDisposable
    {
        private readonly Slot slot;
        private Session? loginSession;
        private readonly IBokPinProvider bokPinProvider;
        private readonly Pkcs11 pkcs11;

        public EidRsaCryptoAccessor(string pkcs11Libpath, IBokPinProvider bokPinProvider, string tokenLabel = null)
        {
            if (pkcs11Libpath == null)
            {
                throw new ArgumentNullException(nameof(pkcs11Libpath));
            }

            if (bokPinProvider == null)
            {
                throw new ArgumentNullException(nameof(bokPinProvider));
            }

            if (tokenLabel == null)
            {
                tokenLabel = "SIG_EP";
            }

            this.bokPinProvider = bokPinProvider;
            this.pkcs11 = new Pkcs11(pkcs11Libpath, AppType.MultiThreaded);
            try
            {
                List<Slot> slots = this.pkcs11.GetSlotList(SlotsType.WithTokenPresent);
                this.slot = slots.SingleOrDefault(t => string.IsNullOrEmpty(tokenLabel) || string.Equals(t.GetTokenInfo().Label, tokenLabel, StringComparison.Ordinal));
                if (this.slot == null)
                {
                    throw new ArgumentException($"PKCS#11 lib '{pkcs11Libpath}' can not contains slot with label '{tokenLabel}'.");
                }

                this.loginSession = null;
            }
            catch (Exception)
            {
                this.loginSession?.Dispose();
                this.pkcs11.Dispose();
                throw;
            }
        }

        private async Task EsnhueLoginSession()
        {
            if (this.loginSession == null)
            {
                byte[]? pin = await this.bokPinProvider.GetBokPin();
                try
                {
                    Session session = this.slot.OpenSession(SessionType.ReadOnly);
                    session.Login(CKU.CKU_USER, pin);

                    this.loginSession = session;
                }
                finally
                {
                    if (pin != null)
                    {
                        Array.Clear(pin, 0, pin.Length);
                    }
                }
            }
        }

        public async Task<byte[]> AsymetricDecrypt(string certificateThumbprint, byte[] data, RSAEncryptionPadding padding)
        {
            if (certificateThumbprint == null) throw new ArgumentNullException(nameof(certificateThumbprint));
            if (data == null) throw new ArgumentNullException(nameof(data));

            await this.EsnhueLoginSession();

            using (Session session = this.slot.OpenSession(SessionType.ReadOnly))
            {
                (byte[] ckaId, byte[] ckaLabel, _) = this.FindCertificates(session)
                         .First(t => string.Equals(new X509Certificate2(t.ckaValue).Thumbprint, certificateThumbprint, StringComparison.OrdinalIgnoreCase));

                ObjectHandle privateKey = this.FindPrivateKey(session, ckaLabel, ckaId);
                using (Mechanism decryptMechanism = this.CreateDecryptMechanism(padding))
                {
                    return session.Decrypt(decryptMechanism, privateKey, data);
                }
            }
        }

        private Mechanism CreateDecryptMechanism(RSAEncryptionPadding padding)
        {
            if (padding.Equals(RSAEncryptionPadding.Pkcs1))
            {
                return new Mechanism(CKM.CKM_RSA_PKCS);
            }

            throw new SlovakEidDecryptionException("Unsuported mechanism");

            //if (padding.Equals(RSAEncryptionPadding.OaepSHA1))
            //{
            //    return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new Net.Pkcs11Interop.HighLevelAPI.MechanismParams.CkRsaPkcsOaepParams((ulong)CKM.CKM_SHA_1, (ulong)CKG.CKG_MGF1_SHA1, (ulong)CKZ.CKZ_DATA_SPECIFIED, null));
            //}

            //if (padding.Equals(RSAEncryptionPadding.OaepSHA256))
            //{
            //    return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new Net.Pkcs11Interop.HighLevelAPI.MechanismParams.CkRsaPkcsOaepParams((ulong)CKM.CKM_SHA256, (ulong)CKG.CKG_MGF1_SHA256, (ulong)CKZ.CKZ_DATA_SPECIFIED, null));
            //}

            //if (padding.Equals(RSAEncryptionPadding.OaepSHA384))
            //{
            //    return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new Net.Pkcs11Interop.HighLevelAPI.MechanismParams.CkRsaPkcsOaepParams((ulong)CKM.CKM_SHA384, (ulong)CKG.CKG_MGF1_SHA384, (ulong)CKZ.CKZ_DATA_SPECIFIED, null));
            //}

            //if (padding.Equals(RSAEncryptionPadding.OaepSHA512))
            //{
            //    return new Mechanism(CKM.CKM_RSA_PKCS_OAEP, new Net.Pkcs11Interop.HighLevelAPI.MechanismParams.CkRsaPkcsOaepParams((ulong)CKM.CKM_SHA512, (ulong)CKG.CKG_MGF1_SHA512, (ulong)CKZ.CKZ_SALT_SPECIFIED, null));
            //}
        }

        public async Task<X509Certificate2> ExtractPublicCertificate()
        {
            await this.EsnhueLoginSession();
            using (Session session = this.slot.OpenSession(SessionType.ReadOnly))
            {
                return this.FindCertificates(session)
                    .Select(t => new X509Certificate2(t.ckaValue))
                      .First(t => this.IsEncryptedCertificate(t));
            }
        }

        public void Dispose()
        {
            this.Dispose(true);
        }

        private bool IsEncryptedCertificate(X509Certificate2 cert)
        {
            foreach (X509KeyUsageExtension extension in cert.Extensions.OfType<X509KeyUsageExtension>())
            {
                if (extension.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                {
                    return true;
                }
            }

            return false;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.loginSession?.Dispose();
                this.pkcs11.Dispose();
            }
        }

        private ObjectHandle FindPrivateKey(Session session, byte[] ckaLabel, byte[] ckaId)
        {
            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_LABEL, ckaLabel),
                new ObjectAttribute(CKA.CKA_ID, ckaId)
            };

            return session.FindAllObjects(searchTemplate).Single();
        }

        private IEnumerable<(byte[] ckaId, byte[] ckaLabel, byte[] ckaValue)> FindCertificates(Session session)
        {
            List<ObjectAttribute> searchTemplate = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
            };

            foreach (ObjectHandle certHandle in session.FindAllObjects(searchTemplate))
            {
                List<ObjectAttribute> objectAttributes = session.GetAttributeValue(certHandle, new List<CKA>() { CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_VALUE });

                byte[] ckaId = objectAttributes[0].GetValueAsByteArray();
                byte[] ckaLabel = objectAttributes[1].GetValueAsByteArray();
                byte[] ckaValue = objectAttributes[2].GetValueAsByteArray();

                yield return (ckaId, ckaLabel, ckaValue);
            }
        }
    }
}
