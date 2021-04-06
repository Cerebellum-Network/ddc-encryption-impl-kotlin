package network.cere.ddc.crypto.v1.decrypt

import network.cere.ddc.crypto.v1.TypeHint

class RawDataDecrypter(decryptionConfig: DecryptionConfig) : AbstractDecrypter(decryptionConfig) {
    override val supportedDataType: TypeHint = TypeHint.RAW

    override fun decrypt(data: ByteArray): ByteArray {
        return aeadCache.values.first().decrypt(data, null)
    }
}
