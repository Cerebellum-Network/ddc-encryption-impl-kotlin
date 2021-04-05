package network.cere.ddc.crypto.v1.encrypt

import network.cere.ddc.crypto.v1.TypeHint

data class EncryptionConfig(
    val masterKeyHex: String,
    val typeHint: TypeHint,
    val jsonPathsToEncrypt: List<String> = listOf("$..*")
)
