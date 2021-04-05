package network.cere.ddc.crypto.v1.decrypt

import network.cere.ddc.crypto.v1.TypeHint

data class DecryptionConfig(
    val typeHint: TypeHint,
    val pathToDecryptToDecryptionKeyHex: Map<String, String>
)
