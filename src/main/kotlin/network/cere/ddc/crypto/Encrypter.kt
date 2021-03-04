package network.cere.ddc.crypto

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.crypto.tink.Aead
import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.rfksystems.blake2b.security.Blake2b256Digest
import network.cere.ddc.crypto.TypeHint.*

class Encrypter(
    private val objectMapper: ObjectMapper,
    private val encryptionConfig: EncryptionConfig
) {
    private companion object {
        private const val DEFAULT_SCOPE_NAME = "__default_scope"
    }

    private val scopedFields = encryptionConfig.scopes
        .map(EncryptionConfig.Scope::fields)
        .flatten()
        .toSet()
    val scopeToKey: Map<String, ByteArray> = encryptionConfig.scopes
        .map(EncryptionConfig.Scope::name)
        .plus(DEFAULT_SCOPE_NAME)
        .map { it to encryptionConfig.masterKey.toByteArray() + it.toByteArray() }
        .toMap()
        .mapValues { Blake2b256Digest().apply { update(it.value) }.digest() }
    private val scopeToAead: Map<String, Aead> = scopeToKey.mapValues { XChaCha20Poly1305(it.value) }

    fun encrypt(data: ByteArray, typeHint: TypeHint = UNKNOWN): ByteArray {
        return when (typeHint) {
            JSON -> encryptJson(data)
            RAW -> encryptRaw(data)
            UNKNOWN -> if (tryToParseJson(data) != null) encryptJson(data) else encryptRaw(data)
        }
    }

    private fun encryptJson(data: ByteArray): ByteArray {
        val jsonNode = tryToParseJson(data) ?: throw IllegalArgumentException("Unable to parse JSON")
        val defaultScopeFields = jsonNode.fieldNames()
            .asSequence()
            .filterNot { it in scopedFields }
            .toSet()
        return encryptionConfig.scopes
            .asSequence()
            .map { it.name to scopeData(jsonNode, it.fields) }
            .plus(DEFAULT_SCOPE_NAME to scopeData(jsonNode, defaultScopeFields))
            .filterNot { it.second.isEmpty() }
            .map { it.first to objectMapper.writeValueAsBytes(it.second) }
            .map { it.first to encrypt(it.first, it.second) }
            .toMap()
            .let(objectMapper::writeValueAsBytes)
    }

    private fun encryptRaw(data: ByteArray): ByteArray {
        return mapOf(DEFAULT_SCOPE_NAME to encrypt(DEFAULT_SCOPE_NAME, data))
            .let(objectMapper::writeValueAsBytes)
    }

    private fun scopeData(jsonNode: JsonNode, scopeFields: Iterable<String>): Map<String, JsonNode> {
        return scopeFields.asSequence()
            .filter(jsonNode::has)
            .map { it to jsonNode.get(it) }
            .toMap()
    }

    private fun tryToParseJson(data: ByteArray): JsonNode? = runCatching {
        objectMapper.readTree(data)
    }.getOrNull()

    private fun encrypt(scope: String, data: ByteArray): String {
        return scopeToAead.getValue(scope)
            .encrypt(data, null)
            .let(Hex::encode)
    }
}
