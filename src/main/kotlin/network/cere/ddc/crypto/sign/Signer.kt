package network.cere.ddc.crypto.sign

import com.google.crypto.tink.subtle.Hex

interface Signer {
    val algorithm: SignatureAlgorithm

    fun signToBytes(message: String) = signToBytes(message.toByteArray())

    fun signToHex(message: String): String = signToHex(message.toByteArray())

    fun signToHex(message: ByteArray): String = Hex.encode(signToBytes(message))

    fun signToBytes(message: ByteArray): ByteArray
}
