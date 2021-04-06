package network.cere.ddc.crypto.v1.encrypt

import network.cere.ddc.crypto.v1.TypeHint

interface Encrypter {
    val supportedDataType: TypeHint

    fun encrypt(data: ByteArray): ByteArray
}
