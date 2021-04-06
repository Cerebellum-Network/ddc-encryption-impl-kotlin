package network.cere.ddc.crypto.v1.encrypt

data class EncryptionConfig(
    val masterKeyHex: String,
    val jsonPathsToEncrypt: List<String> = listOf("$..*")
)
