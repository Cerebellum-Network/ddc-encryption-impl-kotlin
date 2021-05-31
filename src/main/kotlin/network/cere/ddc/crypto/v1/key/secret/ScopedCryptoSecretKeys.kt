package network.cere.ddc.crypto.v1.key.secret

import network.cere.ddc.crypto.v1.key.secret.CryptoSecretKey.Companion.JSON_ROOT_PATH
import network.cere.ddc.crypto.v1.traverse

class ScopedCryptoSecretKeys(val pathToDecryptToDecryptionKeyHex: Map<String, String>) {
    constructor(rootKeyHex: String) : this(mapOf(JSON_ROOT_PATH to rootKeyHex))

    fun decryptWithScopes(data: String): String {
        val onMatch: (String, String) -> String = { path, value ->
            CryptoSecretKey(pathToDecryptToDecryptionKeyHex.getValue(path)).decryptDirectly(value)
        }
        val onSuccess: (String) -> String = { it }
        val onFailure: () -> String =
            { CryptoSecretKey(pathToDecryptToDecryptionKeyHex.getValue(JSON_ROOT_PATH)).decryptDirectly(data) }
        return traverse(data, onMatch, onSuccess, onFailure, pathToDecryptToDecryptionKeyHex.keys)
    }
}
