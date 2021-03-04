package network.cere.ddc.crypto

import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

internal class IntegrationTest {
    private val objectMapper = ObjectMapper()
    private val encrypter = Encrypter(
        objectMapper,
        EncryptionConfig(
            "super-secret", listOf(
                EncryptionConfig.Scope("geo_location", listOf("geo_location", "address")),
                EncryptionConfig.Scope("private_info", listOf("name", "dob", "address"))
            )
        )
    )
    private val decrypter = Decrypter(objectMapper)

    @Test
    fun `Encrypt and decrypt JSON`() {
        //given
        val json = """{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}"""
            .toByteArray()

        //when
        val encrypted = encrypter.encrypt(json)
        val decrypted = decrypter.decrypt(encrypted, encrypter.scopeToKey)

        //then
        assertArrayEquals(json, decrypted)
    }

    @Test
    fun `Encrypt and decrypt raw data`() {
        //given
        val data = "abc".toByteArray()

        //when
        val encrypted = encrypter.encrypt(data)
        val decrypted = decrypter.decrypt(encrypted, encrypter.scopeToKey)

        //then
        assertArrayEquals(data, decrypted)
    }
}
