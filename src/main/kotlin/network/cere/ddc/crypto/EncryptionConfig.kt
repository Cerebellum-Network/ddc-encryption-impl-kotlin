package network.cere.ddc.crypto

data class EncryptionConfig(
    val masterKey: String,
    val scopes: List<Scope> = emptyList()
) {
    data class Scope(
        val name: String,
        val fields: List<String> = emptyList()
    )
}
