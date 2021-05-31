package network.cere.ddc.crypto.v1.key

import java.security.PrivateKey
import java.security.PublicKey

abstract class KeyPair<PK : PublicKey, SK : PrivateKey>(val publicKey: PK, val privateKey: SK)
