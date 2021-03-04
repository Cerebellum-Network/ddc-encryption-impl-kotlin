package network.cere.ddc.crypto

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.crypto.tink.subtle.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

internal class EncrypterTest {
    private val objectMapper = ObjectMapper()
    private val testSubject = Encrypter(
        objectMapper,
        EncryptionConfig(
            "super-secret", listOf(
                EncryptionConfig.Scope("geo_location", listOf("geo_location", "address")),
                EncryptionConfig.Scope("private_info", listOf("name", "dob", "address"))
            )
        )
    )

    @Test
    fun `Encrypt JSON with all scopes`() {
        testJsonEncryption(
            """
            {
                "name": {
                    "first": "John", 
                    "second": "Doe"
                },
                "address": "abc",
                "dob": "09-12-1988",
                "event": "CLICK"
            }
        """.trimIndent(),
            setOf("geo_location", "private_info", "__default_scope")
        )
    }

    @Test
    fun `Encrypt JSON without scopes`() {
        testJsonEncryption("""{"event": "CLICK"}""", setOf("__default_scope"))
    }

    @Test
    fun `Encrypt JSON with some scopes`() {
        testJsonEncryption(
            """
            {
                "name": {
                    "first": "John", 
                    "second": "Doe"
                },
                "dob": "09-12-1988"
            }
        """.trimIndent(),
            setOf("private_info")
        )
    }

    @Test
    fun `Encrypt JSON with crossing scopes`() {
        testJsonEncryption("""{"address": "abc"}""", setOf("geo_location", "private_info"))
    }

    private fun testJsonEncryption(json: String, expectedFields: Set<String>) {
        //given
        val data = json.toByteArray()

        //when
        val result = testSubject.encrypt(data, TypeHint.JSON)
            .let(objectMapper::readTree)

        //then
        val fields = result.fieldNames().asSequence().toSet()
        assertEquals(expectedFields, fields)
    }

    @Test
    fun `Encrypt JSON with invalid JSON`() {
        assertThrows(IllegalArgumentException::class.java) {
            testSubject.encrypt("{zzz}".toByteArray(), TypeHint.JSON)
        }
    }

    @Test
    fun `Encrypt raw data encryption`() {
        //given
        val data = "abc".toByteArray()

        //when
        val result = testSubject.encrypt(data, TypeHint.RAW)
            .let(objectMapper::readTree)

        //then
        val fields = result.fieldNames().asSequence().toSet()
        assertEquals(setOf("__default_scope"), fields)
    }

    @Test
    fun `Test unknown data encryption with JSON`() {
        //given
        val data = """
            {
                "name": {
                    "first": "John", 
                    "second": "Doe"
                },
                "address": "abc",
                "dob": "09-12-1988",
                "event": "CLICK"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.encrypt(data)
            .let(objectMapper::readTree)

        //then
        val fields = result.fieldNames().asSequence().toSet()
        assertEquals(setOf("geo_location", "private_info", "__default_scope"), fields)
    }

    @Test
    fun `Test unknown data encryption with raw data`() {
        //given
        val data = "raw".toByteArray()

        //when
        val result = testSubject.encrypt(data)
            .let(objectMapper::readTree)

        //then
        val fields = result.fieldNames().asSequence().toSet()
        assertEquals(setOf("__default_scope"), fields)
    }

    @Test
    fun `Get scope keys`() {
        //when
        val result = testSubject.scopeToKey.mapValues { Hex.encode(it.value) }

        //then
        assertEquals(
            mapOf(
                "geo_location" to "dd88bb36437495f1ae0f857abb5c0fe33bd17a73ee48da372637dabf40a84d0c",
                "private_info" to "e661a2888f75ca33b9b74cefd2b88559b2ea595da8fc01128a06069d8bab62ae",
                "__default_scope" to "c9ab4a99fbbb89b4e51fffc9b42b80ce50788db93edaa5b3fa991d756b6164e4"
            ), result
        )
    }
}
