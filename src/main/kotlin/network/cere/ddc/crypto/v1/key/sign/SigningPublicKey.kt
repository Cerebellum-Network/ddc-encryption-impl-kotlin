package network.cere.ddc.crypto.v1.key.sign

import com.iwebpp.crypto.TweetNaclFast
import network.cere.ddc.crypto.v1.hexToBytes
import network.cere.ddc.crypto.v1.key.crypto.CryptoPublicKey
import java.security.PublicKey

class SigningPublicKey(private val keyBytes: ByteArray) : PublicKey {
    constructor(hexString: String) : this(hexString.hexToBytes())

    private val spiSignature = TweetNaclFast.Signature(keyBytes, null)

    override fun getAlgorithm(): String = ALGORITHM

    override fun getFormat(): String = FORMAT

    override fun getEncoded(): ByteArray = keyBytes

    fun isValidSignature(message: String, signatureHex: String): Boolean {
        return spiSignature.detached_verify(message.toByteArray(), signatureHex.hexToBytes())
    }

    fun toCryptoPublicKey(): CryptoPublicKey {
        val z = ByteArray(32)
        val q = Array(4) { LongArray(16) }
        val a = LongArray(16)
        val b = LongArray(16)
        unpackneg(q, keyBytes)
        val y = q[1]
        A(a, gf1, y)
        Z(b, gf1, y)
        inv25519(b, b)
        M(a, a, b)
        pack25519(z, a, 0)
        return CryptoPublicKey(z)
    }
}
