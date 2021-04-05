package network.cere.ddc.crypto.v1

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.crypto.tink.subtle.Hex
import network.cere.ddc.crypto.v1.decrypt.Decrypter
import network.cere.ddc.crypto.v1.decrypt.DecryptionConfig
import network.cere.ddc.crypto.v1.encrypt.Encrypter
import network.cere.ddc.crypto.v1.encrypt.EncryptionConfig
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test

internal class IntegrationTest {
    private val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())

    @Test
    fun `Encrypt and decrypt raw`() {
        //given
        val encrypter = Encrypter(EncryptionConfig(masterKeyHex, TypeHint.RAW))
        val decrypter = Decrypter(
            DecryptionConfig(
                TypeHint.RAW,
                mapOf("" to masterKeyHex)
            )
        )
        val data = "raw data".toByteArray()

        //when
        val result = decrypter.decrypt(encrypter.encrypt(data))

        //then
        assertArrayEquals(data, result)
    }

    @Test
    fun `Encrypt and decrypt JSON`() {
        //given
        val encrypter = Encrypter(EncryptionConfig(masterKeyHex, TypeHint.JSON, listOf("$.k1")))
        val decrypter = Decrypter(
            DecryptionConfig(
                TypeHint.JSON,
                mapOf("$.k1" to "0ae19ba1e42a63aefea507a19df00ffc962bc894b3fb720723d45e456f636977")
            )
        )
        val data = """
            {
                "k1": "v1",
                "k2": "v2",
                "k3": {
                    "k4": true,
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": 123
                    }
                }
            }
        """.trimIndent().toByteArray()

        //when
        val result = decrypter.decrypt(encrypter.encrypt(data))

        //then
        assertArrayEquals(ObjectMapper().let { it.writeValueAsBytes(it.readTree(data)) }, result)
    }
}
