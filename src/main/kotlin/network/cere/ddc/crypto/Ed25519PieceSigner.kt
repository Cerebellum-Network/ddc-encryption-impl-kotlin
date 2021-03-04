package network.cere.ddc.crypto

import com.google.crypto.tink.subtle.Ed25519Sign

class Ed25519Signer(private val privateKey: ByteArray) {
    private val sign = Ed25519Sign(privateKey)

    fun sign(message: ByteArray) = sign.sign(message)
}
