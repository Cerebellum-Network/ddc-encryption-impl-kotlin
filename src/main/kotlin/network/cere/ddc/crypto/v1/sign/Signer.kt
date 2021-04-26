package network.cere.ddc.crypto.v1.sign

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.utils.Key

class Signer(private val sodium: LazySodium, privateKeyHex: String) {
    private val secretKey = Key.fromHexString(privateKeyHex)

    fun sign(message: String): String {
        return sodium.cryptoSignDetached(message, secretKey)
    }
}
