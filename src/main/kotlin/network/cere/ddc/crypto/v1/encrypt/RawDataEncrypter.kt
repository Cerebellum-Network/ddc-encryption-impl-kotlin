package network.cere.ddc.crypto.v1.encrypt

import network.cere.ddc.crypto.v1.TypeHint

class RawDataEncrypter(encryptionConfig: EncryptionConfig) : AbstractEncrypter(encryptionConfig) {
    override val supportedDataType: TypeHint = TypeHint.RAW

    override fun encrypt(data: ByteArray): ByteArray {
        return masterAead.encrypt(data, null)
    }
}
