import CommonCrypto
func encrypt(_ data: Data, key: Data, iv: Data) -> Data? {
    var out = Data(count: data.count + kCCBlockSizeAES128)
    var moved = 0
    let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                         (key as NSData).bytes, key.count, (iv as NSData).bytes, (data as NSData).bytes, data.count,
                         out.withUnsafeMutableBytes { $0.baseAddress }, out.count, &moved)
    return status == kCCSuccess ? out.prefix(moved) : nil
}
