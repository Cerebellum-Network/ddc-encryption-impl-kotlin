package network.cere.ddc.crypto.v1.key.secret

import com.iwebpp.crypto.TweetNaclFast
import com.rfksystems.blake2b.security.Blake2b256Digest
import network.cere.ddc.crypto.v1.hexToBytes
import network.cere.ddc.crypto.v1.toHex
import network.cere.ddc.crypto.v1.traverse
import javax.crypto.SecretKey

class CryptoSecretKey(private val keyBytes: ByteArray) : SecretKey {
    constructor(hexString: String) : this(hexString.hexToBytes())

    internal companion object {
        private const val PATH_SEPARATOR = '/'
        internal const val JSON_ROOT_PATH = "$"
        internal const val ALL_PATHS = "$..*"
    }

    private val emptyNonce = ByteArray(24)

    private val spiBox = TweetNaclFast.SecretBox(keyBytes)

    override fun getAlgorithm(): String = ALGORITHM

    override fun getFormat(): String = FORMAT

    override fun getEncoded(): ByteArray = keyBytes

    fun encryptWithScopes(data: String, jsonPathsToEncrypt: List<String> = listOf(ALL_PATHS)): EncryptionResult {
        val pathToKey = mutableMapOf<String, String>()
        val onMatch: (String, String) -> String = { path, value ->
            val dek = derive(path)
            pathToKey[path] = dek.toHex()
            dek.encryptDirectly(value)
        }
        val onSuccess: (String) -> EncryptionResult = { EncryptionResult(it, ScopedCryptoSecretKeys(pathToKey)) }
        val onFailure: () -> EncryptionResult = {
            val dek = derive(JSON_ROOT_PATH)
            EncryptionResult(dek.encryptDirectly(data), ScopedCryptoSecretKeys(dek.toHex()))
        }

        return traverse(data, onMatch, onSuccess, onFailure, jsonPathsToEncrypt)
    }

    fun encryptDirectly(message: String): String {
        return spiBox.box(message.toByteArray(), emptyNonce).toHex()
    }

    fun decryptWithScopes(data: String, jsonPathsToDecrypt: List<String> = listOf(ALL_PATHS)): String {
        val onMatch: (String, String) -> String = { path, value -> derive(path).decryptDirectly(value) }
        val onSuccess: (String) -> String = { it }
        val onFailure: () -> String = { derive(JSON_ROOT_PATH).decryptDirectly(data) }
        return traverse(data, onMatch, onSuccess, onFailure, jsonPathsToDecrypt)
    }

    fun decryptDirectly(messageHex: String): String {
        return spiBox.open(messageHex.hexToBytes(), emptyNonce).decodeToString()
    }

    fun derive(path: String): CryptoSecretKey {
        val derived = keyBytes + PATH_SEPARATOR.toByte() + path.toByteArray()
        return Blake2b256Digest().digest(derived).let(::CryptoSecretKey)
    }
}
