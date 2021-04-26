package network.cere.ddc.crypto.v1.encrypt

import com.fasterxml.jackson.databind.JsonNode
import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.utils.Key
import com.jayway.jsonpath.JsonPath
import network.cere.ddc.crypto.v1.common.BaseCryptoService
import org.jsfr.json.JacksonParser
import org.jsfr.json.JsonPathListener
import org.jsfr.json.JsonSurfer
import org.jsfr.json.ParsingContext
import org.jsfr.json.provider.JacksonProvider

class Encrypter(
    sodium: LazySodium,
    private val encryptionConfig: EncryptionConfig
) : BaseCryptoService(sodium) {
    private val masterKey = Key.fromHexString(encryptionConfig.masterKeyHex)

    fun encrypt(data: String): Pair<String, Map<String, String>> {
        val surfer = JsonSurfer(JacksonParser.INSTANCE, JacksonProvider.INSTANCE)
        val toReplace = mutableMapOf<String, String>()
        val builder = surfer.configBuilder()
        val pathToKey = mutableMapOf<String, String>()
        encryptionConfig.jsonPathsToEncrypt.forEach {
            builder.bind(it, object : JsonPathListener {
                override fun onValue(value: Any, context: ParsingContext) {
                    val node = value as JsonNode
                    if (node.isValueNode) {
                        val path = context.jsonPath
                        val dek = dek(path)
                        val encrypted = encrypt(node.asText(), Key.fromHexString(dek))
                        toReplace[path] = encrypted
                        pathToKey[path] = dek
                    }
                }
            })
        }
        return runCatching {
            builder.buildAndSurf(data)
        }.fold(
            {
                val ctx = JsonPath.parse(data)
                toReplace.forEach { (p, v) -> ctx.set(p, v) }
                ctx.jsonString() to pathToKey
            },
            {
                val dek = dek(JSON_ROOT_PATH)
                encrypt(data, Key.fromHexString(dek)) to mapOf(JSON_ROOT_PATH to dek)
            }
        )
    }

    private fun dek(path: String): String {
        return sodium.cryptoGenericHash(path, masterKey)
    }
}
