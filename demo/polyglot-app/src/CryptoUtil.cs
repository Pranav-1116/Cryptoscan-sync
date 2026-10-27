using System.Security.Cryptography;

public class CryptoUtil
{
    public static SymmetricAlgorithm Weak()
    {
        return DES.Create();
    }

    public static SymmetricAlgorithm Strong()
    {
        return Aes.Create();
    }

    public static HashAlgorithm Digest()
    {
        return MD5.Create();
    }

    public static RSA Keys()
    {
        return RSA.Create(2048);
    }

    public void Hardcoded()
    {
        var aes = Aes.Create();
        aes.Key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    }
}
