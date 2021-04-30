package network.cere.ddc.crypto.v1.decrypt

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

class Decrypter(
    sodium: LazySodium,
    private val pathToDecryptToDecryptionKeyHex: Map<String, String>
) : BaseCryptoService(sodium) {
    fun decrypt(data: String): String {
        val surfer = JsonSurfer(JacksonParser.INSTANCE, JacksonProvider.INSTANCE)
        val toReplace = mutableMapOf<String, String>()
        val builder = surfer.configBuilder()
        pathToDecryptToDecryptionKeyHex.forEach {
            builder.bind(it.key, object : JsonPathListener {
                override fun onValue(value: Any, context: ParsingContext) {
                    val node = value as JsonNode
                    if (node.isValueNode) {
                        val path = context.jsonPath
                        toReplace[path] = decrypt(node.textValue(), Key.fromHexString(it.value))
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
                ctx.jsonString()
            },
            {
                decrypt(data, Key.fromHexString(pathToDecryptToDecryptionKeyHex[JSON_ROOT_PATH]))
            }
        )
    }
}
