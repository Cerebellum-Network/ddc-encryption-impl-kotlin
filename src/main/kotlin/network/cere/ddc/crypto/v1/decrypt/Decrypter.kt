package network.cere.ddc.crypto.v1.decrypt

import network.cere.ddc.crypto.v1.TypeHint

interface Decrypter {
    val supportedDataType: TypeHint

    fun decrypt(data: ByteArray): ByteArray
}
