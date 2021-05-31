package network.cere.ddc.crypto.v1.key.sign

import cash.z.ecc.android.bip39.Mnemonics
import com.iwebpp.crypto.TweetNaclFast
import org.apache.commons.codec.digest.HmacAlgorithms
import org.apache.commons.codec.digest.HmacUtils
import kotlin.experimental.xor

private const val SUBSTRATE_KEY_LENGTH = 32

fun signingKeyPairFromMnemonic(mnemonic: String): SigningKeyPair {
    val seed = Mnemonics.MnemonicCode(mnemonic).use {
        val entropy = it.toEntropy()
        val salt = Mnemonics.DEFAULT_PASSPHRASE.toByteArray()
        pbkdf2(entropy, salt).sliceArray(0 until SUBSTRATE_KEY_LENGTH)
    }
    val kp = TweetNaclFast.Signature.keyPair_fromSeed(seed)
    return SigningKeyPair(kp.publicKey, kp.secretKey)
}

private fun pbkdf2(password: ByteArray, salt: ByteArray): ByteArray {
    val block = salt + byteArrayOf(0, 0, 0, 1)
    var prev = hmac(password, block)
    val md = prev.copyOf()
    repeat(Mnemonics.INTERATION_COUNT - 1) {
        prev = hmac(password, prev)
        prev.forEachIndexed { i, b ->
            md[i] = md[i] xor b
        }
    }
    return md
}

private fun hmac(password: ByteArray, data: ByteArray): ByteArray {
    return HmacUtils.getInitializedMac(HmacAlgorithms.HMAC_SHA_512, password)
        .apply { update(data) }
        .doFinal()
}
