package network.cere.ddc.crypto.v1.key.crypto

import network.cere.ddc.crypto.v1.key.KeyPair

class CryptoKeyPair(publicKey: CryptoPublicKey, privateKey: CryptoPrivateKey) :
    KeyPair<CryptoPublicKey, CryptoPrivateKey>(publicKey, privateKey) {

    constructor(publicKeyBytes: ByteArray, privateKeyBytes: ByteArray) : this(
        CryptoPublicKey(publicKeyBytes),
        CryptoPrivateKey(privateKeyBytes)
    )

    constructor(publicKeyHex: String, privateKeyHex: String) : this(
        CryptoPublicKey(publicKeyHex),
        CryptoPrivateKey(privateKeyHex)
    )
}
