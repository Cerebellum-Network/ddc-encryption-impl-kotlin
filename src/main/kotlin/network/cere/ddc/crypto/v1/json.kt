package network.cere.ddc.crypto.v1

import com.fasterxml.jackson.databind.JsonNode
import com.jayway.jsonpath.JsonPath
import network.cere.ddc.crypto.v1.key.secret.CryptoSecretKey.Companion.ALL_PATHS
import org.jsfr.json.JacksonParser
import org.jsfr.json.JsonPathListener
import org.jsfr.json.JsonSurfer
import org.jsfr.json.ParsingContext
import org.jsfr.json.provider.JacksonProvider

internal inline fun <reified T> traverse(
    json: String,
    crossinline onMatch: (String, String) -> String,
    onSuccess: (String) -> T,
    onFailure: () -> T,
    jsonPathsToProcess: Iterable<String> = setOf(ALL_PATHS)
): T {
    val surfer = JsonSurfer(JacksonParser.INSTANCE, JacksonProvider.INSTANCE)
    val toReplace = mutableMapOf<String, String>()
    val builder = surfer.configBuilder()

    jsonPathsToProcess.forEach {
        builder.bind(it, object : JsonPathListener {
            override fun onValue(value: Any, context: ParsingContext) {
                val node = value as JsonNode
                if (node.isValueNode) {
                    val path = context.jsonPath
                    toReplace[path] = onMatch(path, node.asText())
                }
            }
        })
    }
    return runCatching {
        builder.buildAndSurf(json)
    }.fold(
        {
            val ctx = JsonPath.parse(json)
            toReplace.forEach { (p, v) -> ctx.set(p, v) }
            onSuccess(ctx.jsonString())
        },
        { onFailure() }
    )
}
