package network.cere.ddc.crypto.v1.sign

import com.google.crypto.tink.subtle.Ed25519Sign

class Ed25519Signer(privateKey: ByteArray) : Signer {
    private val sign = Ed25519Sign(privateKey)

    override val algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519

    override fun signToBytes(message: ByteArray): ByteArray = sign.sign(message)
}
