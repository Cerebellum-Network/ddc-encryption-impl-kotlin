package network.cere.ddc.crypto.v1.sign

import io.emeraldpay.polkaj.schnorrkel.Schnorrkel

class Sr25519Signer(privateKey: ByteArray) : Signer {
    private val schnorrkel = Schnorrkel.getInstance()
    private val keyPair = Schnorrkel.KeyPair(ByteArray(32), privateKey)

    override val algorithm: SignatureAlgorithm = SignatureAlgorithm.SR25519

    override fun signToBytes(message: ByteArray): ByteArray = schnorrkel.sign(message, keyPair)
}
