package network.cere.ddc.crypto.v1.encrypt

import com.fasterxml.jackson.databind.JsonNode
import com.google.crypto.tink.Aead
import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.jayway.jsonpath.Configuration
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.Option
import com.jayway.jsonpath.spi.json.JacksonJsonProvider
import com.jayway.jsonpath.spi.json.JsonProvider
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider
import com.jayway.jsonpath.spi.mapper.MappingProvider
import com.rfksystems.blake2b.security.Blake2b256Digest
import network.cere.ddc.crypto.v1.TypeHint
import org.jsfr.json.JacksonParser
import org.jsfr.json.JsonPathListener
import org.jsfr.json.JsonSurfer
import org.jsfr.json.ParsingContext
import org.jsfr.json.provider.JacksonProvider
import java.util.*
import java.util.concurrent.ConcurrentHashMap

class JsonDataEncrypter(encryptionConfig: EncryptionConfig) : AbstractEncrypter(encryptionConfig) {
    private val aeadCache = ConcurrentHashMap<String, Aead>()

    init {
        Configuration.setDefaults(object : Configuration.Defaults {
            private val jsonProvider = JacksonJsonProvider()
            private val mappingProvider = JacksonMappingProvider()
            override fun jsonProvider(): JsonProvider = jsonProvider
            override fun options(): Set<Option> = EnumSet.noneOf(Option::class.java)
            override fun mappingProvider(): MappingProvider = mappingProvider
        })
    }

    override val supportedDataType: TypeHint = TypeHint.JSON

    override fun encrypt(data: ByteArray): ByteArray {
        val surfer = JsonSurfer(JacksonParser.INSTANCE, JacksonProvider.INSTANCE)
        val toReplace = mutableMapOf<String, String>()
        val builder = surfer.configBuilder()
        encryptionConfig.jsonPathsToEncrypt.forEach {
            builder.bind(it, object : JsonPathListener {
                override fun onValue(value: Any, context: ParsingContext) {
                    val node = value as JsonNode
                    if (node.isValueNode) {
                        val path = context.jsonPath
                        toReplace[path] = Hex.encode(derivedAead(path).encrypt(node.asText().toByteArray(), null))
                    }
                }
            })
        }
        data.inputStream().use(builder::buildAndSurf)
        val ctx = data.inputStream().use(JsonPath::parse)
        toReplace.forEach { (p, v) -> ctx.set(p, v) }
        return ctx.jsonString().toByteArray()
    }

    private fun derivedAead(path: String): Aead {
        return aeadCache.computeIfAbsent(path) {
            Blake2b256Digest()
                .apply { update(masterKey + path.toByteArray()) }
                .digest()
                .let(::XChaCha20Poly1305)
        }
    }
}
