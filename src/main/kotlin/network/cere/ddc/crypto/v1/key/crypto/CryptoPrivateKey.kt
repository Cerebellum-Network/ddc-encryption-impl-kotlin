package network.cere.ddc.crypto.v1.key.crypto

import com.iwebpp.crypto.TweetNaclFast
import network.cere.ddc.crypto.v1.hexToBytes
import network.cere.ddc.crypto.v1.key.secret.CryptoSecretKey
import java.security.PrivateKey

class CryptoPrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    constructor(hexString: String) : this(hexString.hexToBytes())

    override fun getAlgorithm(): String = ALGORITHM

    override fun getFormat(): String = FORMAT

    override fun getEncoded(): ByteArray = keyBytes

    fun sealFor(message: String, theirPublicKey: CryptoPublicKey): String {
        val k = ByteArray(32)
        TweetNaclFast.crypto_box_beforenm(k, theirPublicKey.encoded, keyBytes)
        return CryptoSecretKey(k).encryptDirectly(message)
    }

    fun openFrom(sender: CryptoPublicKey, sealedHex: String): String {
        val k = ByteArray(32)
        TweetNaclFast.crypto_box_beforenm(k, sender.encoded, keyBytes)
        return CryptoSecretKey(k).decryptDirectly(sealedHex)
    }
}
