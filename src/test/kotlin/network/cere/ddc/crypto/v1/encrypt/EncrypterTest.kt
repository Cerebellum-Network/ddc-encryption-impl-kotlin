package network.cere.ddc.crypto.v1.encrypt

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.jayway.jsonpath.JsonPath
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test

internal class EncrypterTest {
    private val sodium = LazySodiumJava(SodiumJava())
    private val masterKeyHex = LazySodium.toHex("super-secret".toByteArray())

    @Test
    fun `Encrypt all fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex)
        val encrypter = Encrypter(sodium, config)
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
        """.trimIndent()

        //when
        val result = encrypter.encrypt(data)

        //then
        val ctx = JsonPath.parse(result.first)
        val values = ctx.read<List<Any>>("$..*").filterIsInstance<String>()
        assertEquals(6, values.size)
    }

    @Test
    fun `Encrypt some fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex, listOf("$.k3..*"))
        val encrypter = Encrypter(sodium, config)
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
        """.trimIndent()

        //when
        val result = encrypter.encrypt(data)

        //then
        val ctx = JsonPath.parse(result.first)
        val values = ctx.read<List<Any>>("$..*").filter { it is String || it is Number }
        assertEquals(6, values.size)
        assertEquals("v1", values[0])
        assertEquals("v2", values[1])
        assertNotEquals("true", values[2])
        assertNotEquals("v5", values[3])
        assertNotEquals("v5", values[4])
        assertEquals(123, values[5])
    }

    @Test
    fun `Encrypt raw data`() {
        //given
        val config = EncryptionConfig(masterKeyHex)
        val encrypter = Encrypter(sodium, config)
        val data = "raw data"

        //when
        val result = encrypter.encrypt(data)

        //then
        assertEquals(48, result.first.length)
    }
}
