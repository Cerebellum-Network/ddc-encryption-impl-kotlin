package network.cere.ddc.crypto.v1.encrypt

import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.jayway.jsonpath.JsonPath
import network.cere.ddc.crypto.v1.TypeHint
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class EncrypterTest {
    private val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())

    @Test
    fun `Encrypt raw data`() {
        //given
        val config = EncryptionConfig(masterKeyHex, TypeHint.RAW)
        val encrypter = Encrypter(config)
        val data = "raw data".toByteArray()

        //when
        val result = encrypter.encrypt(data)

        //then
        assertEquals(48, result.size)
        val decrypted = XChaCha20Poly1305(Hex.decode(masterKeyHex)).decrypt(result, null)
        assertArrayEquals(data, decrypted)
    }

    @Test
    fun `Encrypt all fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex, TypeHint.JSON)
        val encrypter = Encrypter(config)
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
        val result = encrypter.encrypt(data)

        //then
        val ctx = result.inputStream().use(JsonPath::parse)
        val values = ctx.read<List<Any>>("$..*").filterIsInstance<String>()
        assertEquals(6, values.size)
        values.forEach { assertTrue(it.length > 64) }
    }

    @Test
    fun `Encrypt some fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex, TypeHint.JSON, listOf("$.k3..*"))
        val encrypter = Encrypter(config)
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
        val result = encrypter.encrypt(data)

        //then
        val ctx = result.inputStream().use(JsonPath::parse)
        val values = ctx.read<List<Any>>("$..*").filter { it is String || it is Number }
        assertEquals(6, values.size)
        assertEquals("v1", values[0])
        assertEquals("v2", values[1])
        assertNotEquals("true", values[2])
        assertNotEquals("v5", values[3])
        assertNotEquals("v5", values[4])
        assertEquals(123, values[5])
    }
}
