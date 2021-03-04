package network.cere.ddc.crypto

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.crypto.tink.Aead
import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.rfksystems.blake2b.security.Blake2b256Digest
import network.cere.ddc.crypto.TypeHint.*

class Decrypter(private val objectMapper: ObjectMapper) {
    fun decrypt(encryptedData: ByteArray, masterKey: String, typeHint: TypeHint = UNKNOWN): ByteArray {
        val encryptedDataJson = objectMapper.readTree(encryptedData)
        val scopeToKey = encryptedDataJson.fieldNames()
            .asSequence()
            .map { it to masterKey.toByteArray() + it.toByteArray() }
            .toMap()
            .mapValues { Blake2b256Digest().apply { update(it.value) }.digest() }
        return decrypt(encryptedData, scopeToKey, typeHint)
    }

    fun decrypt(encryptedData: ByteArray, scopeToKey: Map<String, ByteArray>, typeHint: TypeHint = UNKNOWN): ByteArray {
        val encryptedDataJson = objectMapper.readTree(encryptedData)
        val decryptedPiecesSequence = encryptedDataJson.fieldNames()
            .asSequence()
            .filter(scopeToKey::containsKey)
            .map { decrypt(encryptedDataJson[it].textValue(), XChaCha20Poly1305(scopeToKey[it])) }
        return when (typeHint) {
            JSON -> this::mergeToJson
            RAW -> this::mergeToRaw
            UNKNOWN -> this::mergeUnknown
        }.invoke(decryptedPiecesSequence)
    }

    private fun mergeToJson(decryptedPiecesSequence: Sequence<ByteArray>): ByteArray {
        return decryptedPiecesSequence.map(objectMapper::readTree)
            .flatMap { it.fields().asSequence() }
            .fold(mutableMapOf<String, JsonNode>()) { res, it -> res.apply { putIfAbsent(it.key, it.value) } }
            .let(objectMapper::writeValueAsBytes)
    }

    private fun mergeToRaw(decryptedPiecesSequence: Sequence<ByteArray>): ByteArray {
        return decryptedPiecesSequence
            .map(ByteArray::decodeToString)
            .joinToString(separator = "")
            .toByteArray()
    }

    private fun mergeUnknown(decryptedPiecesSequence: Sequence<ByteArray>): ByteArray {
        val decryptedPieces = decryptedPiecesSequence.toList()
        return if (decryptedPieces.size == 1) {
            decryptedPieces[0]
        } else {
            val seq = decryptedPieces.asSequence()
            runCatching { mergeToJson(seq) }.getOrElse { mergeToRaw(seq) }
        }
    }

    private fun decrypt(data: String, aead: Aead): ByteArray {
        return aead.decrypt(Hex.decode(data), null)
    }
}
