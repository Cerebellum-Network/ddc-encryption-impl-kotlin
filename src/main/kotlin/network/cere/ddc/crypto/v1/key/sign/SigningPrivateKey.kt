package network.cere.ddc.crypto.v1.key.sign

import com.iwebpp.crypto.TweetNaclFast
import network.cere.ddc.crypto.v1.hexToBytes
import network.cere.ddc.crypto.v1.key.crypto.CryptoPrivateKey
import network.cere.ddc.crypto.v1.toHex
import java.security.PrivateKey
import kotlin.experimental.and
import kotlin.experimental.or

class SigningPrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    constructor(hexString: String) : this(hexString.hexToBytes())

    private val spiSignature = TweetNaclFast.Signature(null, keyBytes)

    override fun getAlgorithm(): String = ALGORITHM

    override fun getFormat(): String = FORMAT

    override fun getEncoded(): ByteArray = keyBytes

    fun signToHex(message: String): String {
        return spiSignature.detached(message.toByteArray()).toHex()
    }

    fun toCryptoPrivateKey(): CryptoPrivateKey {
        val d = ByteArray(64)
        val o = ByteArray(32)
        TweetNaclFast.crypto_hash(d, keyBytes.sliceArray(0 until 32))
        d[0] = d[0] and 248.toByte()
        d[31] = d[31] and 127
        d[31] = d[31] or 64
        for (i in 0 until 32) {
            o[i] = d[i]
        }
        for (i in 0 until 64) {
            d[i] = 0
        }
        return CryptoPrivateKey(o)
    }
}
