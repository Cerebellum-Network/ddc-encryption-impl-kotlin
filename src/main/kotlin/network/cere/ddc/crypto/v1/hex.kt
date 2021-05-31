package network.cere.ddc.crypto.v1

import org.apache.commons.codec.binary.Hex
import java.security.Key

private const val HEX_PREFIX = "0x"

fun ByteArray.toHex(withPrefix: Boolean = true): String {
    val hex = Hex.encodeHexString(this, true)
    return if (withPrefix) """$HEX_PREFIX$hex""" else hex
}

fun String.hexToBytes(): ByteArray = Hex.decodeHex(this.removePrefix(HEX_PREFIX))

fun Key.toHex() = this.encoded.toHex()
