package network.cere.ddc.crypto.v1.common

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.utils.Key

abstract class BaseCryptoService(protected val sodium: LazySodium) {
    protected companion object {
        const val JSON_ROOT_PATH = "$"
    }

    private val emptyNonce = ByteArray(Box.NONCEBYTES)
    private val encryptionMethod = AEAD.Method.XCHACHA20_POLY1305_IETF

    protected fun encrypt(message: String, key: Key) =
        sodium.encrypt(message, null, emptyNonce, key, encryptionMethod)

    protected fun decrypt(cipherHex: String, key: Key) =
        sodium.decrypt(cipherHex, null, emptyNonce, key, encryptionMethod)
}
