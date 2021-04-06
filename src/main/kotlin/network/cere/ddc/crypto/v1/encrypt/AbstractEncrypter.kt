package network.cere.ddc.crypto.v1.encrypt

import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305

abstract class AbstractEncrypter(protected val encryptionConfig: EncryptionConfig) : Encrypter {
    protected val masterKey = Hex.decode(encryptionConfig.masterKeyHex.removePrefix("0x"))
    protected val masterAead = XChaCha20Poly1305(masterKey)
}
