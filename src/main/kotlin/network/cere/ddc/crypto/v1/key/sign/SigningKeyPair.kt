package network.cere.ddc.crypto.v1.key.sign

import network.cere.ddc.crypto.v1.key.KeyPair
import network.cere.ddc.crypto.v1.key.crypto.CryptoKeyPair

class SigningKeyPair(publicKey: SigningPublicKey, privateKey: SigningPrivateKey) :
    KeyPair<SigningPublicKey, SigningPrivateKey>(publicKey, privateKey) {

    constructor(keyPair: java.security.KeyPair) : this(keyPair.public.encoded, keyPair.private.encoded)

    constructor(publicKeyBytes: ByteArray, privateKeyBytes: ByteArray) : this(
        SigningPublicKey(publicKeyBytes),
        SigningPrivateKey(privateKeyBytes)
    )

    constructor(publicKeyHex: String, privateKeyHex: String) : this(
        SigningPublicKey(publicKeyHex),
        SigningPrivateKey(privateKeyHex)
    )

    fun signToHex(message: String): String = privateKey.signToHex(message)

    fun isValidSignature(message: String, signatureHex: String): Boolean =
        publicKey.isValidSignature(message, signatureHex)

    fun toCryptoKeyPair(): CryptoKeyPair = CryptoKeyPair(publicKey.toCryptoPublicKey(), privateKey.toCryptoPrivateKey())
}
