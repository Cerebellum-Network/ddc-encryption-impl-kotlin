package network.cere.ddc.crypto.v1.decrypt

import com.fasterxml.jackson.databind.JsonNode
import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.jayway.jsonpath.JsonPath
import network.cere.ddc.crypto.v1.TypeHint.JSON
import network.cere.ddc.crypto.v1.TypeHint.RAW
import org.jsfr.json.JacksonParser
import org.jsfr.json.JsonPathListener
import org.jsfr.json.JsonSurfer
import org.jsfr.json.ParsingContext
import org.jsfr.json.provider.JacksonProvider

class Decrypter(private val decryptionConfig: DecryptionConfig) {
    private val aeadCache = decryptionConfig.pathToDecryptToDecryptionKeyHex
        .mapValues { XChaCha20Poly1305(Hex.decode(it.value.removePrefix("0x"))) }

    fun decrypt(data: ByteArray): ByteArray {
        return when (decryptionConfig.typeHint) {
            JSON -> decryptJson(data)
            RAW -> decryptRaw(data)
        }
    }

    private fun decryptJson(data: ByteArray): ByteArray {
        val surfer = JsonSurfer(JacksonParser.INSTANCE, JacksonProvider.INSTANCE)
        val toReplace = mutableMapOf<String, ByteArray>()
        val builder = surfer.configBuilder()
        aeadCache.forEach {
            builder.bind(it.key, object : JsonPathListener {
                override fun onValue(value: Any, context: ParsingContext) {
                    val node = value as JsonNode
                    if (node.isValueNode) {
                        val path = context.jsonPath
                        toReplace[path] = it.value.decrypt(Hex.decode(node.textValue()), null)
                    }
                }
            })
        }
        data.inputStream().use(builder::buildAndSurf)
        val ctx = data.inputStream().use(JsonPath::parse)
        toReplace.forEach { (p, v) -> ctx.set(p, v.decodeToString()) }
        return ctx.jsonString().toByteArray()
    }

    private fun decryptRaw(data: ByteArray): ByteArray {
        return aeadCache.values.first().decrypt(data, null)
    }
}
