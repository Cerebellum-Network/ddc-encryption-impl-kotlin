package network.cere.ddc.crypto.v1.key.crypto

import network.cere.ddc.crypto.v1.hexToBytes
import java.security.PublicKey

class CryptoPublicKey(private val keyBytes: ByteArray) : PublicKey {
    constructor(hexString: String) : this(hexString.hexToBytes())

    override fun getAlgorithm(): String = ALGORITHM

    override fun getFormat(): String = FORMAT

    override fun getEncoded(): ByteArray = keyBytes
}
