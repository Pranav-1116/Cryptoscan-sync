using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;

class SystemCryptoSamples
{
    void Weak()
    {
        DES.Create();
        MD5.Create();
        var rsa = RSA.Create(1024);
        rsa.SignData(new byte[] { 1 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    void Strong()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.GCM;
        aes.KeySize = 256;
        SHA256.Create();
    }

    void Bouncy()
    {
        var engine = new AesEngine();
        var digest = new MD5Digest();
    }

    void Hardcoded()
    {
        var aes = Aes.Create();
        aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    }
}
