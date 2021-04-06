package network.cere.ddc.crypto.v1.decrypt

import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305

abstract class AbstractDecrypter(decryptionConfig: DecryptionConfig) : Decrypter {
    protected val aeadCache = decryptionConfig.pathToDecryptToDecryptionKeyHex
        .mapValues { XChaCha20Poly1305(Hex.decode(it.value.removePrefix("0x"))) }
}
