package network.cere.ddc.crypto.v1.decrypt

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class DecrypterTest {
    private val sodium = LazySodiumJava(SodiumJava())

    @Test
    fun `Decrypt JSON`() {
        //given
        val decrypter = Decrypter(
            sodium, mapOf(
                "$.k1" to "5C89065A2389230627757F38B29D8B6F5927F5AA06A1176E97D117FDA613AF96",
                "$.k3.k4" to "E1727CD305EB4189329EDEDDFC7AC7B79C1FE66854D451E9600819A6D75B1B5F"
            )
        )
        val data = """
            {
                "k1": "9F8FCDFA7136E85C49106FCAC32A6EB6D9B1",
                "k2": "v2",
                "k3": {
                    "k4": "55D504384CE68448D8EF349DB391A30447439C13",
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": "72F3E2BBAE18C1D2F4710D4ABBBDFA48F31589"
                    }
                }
            }
        """.trimIndent()

        //when
        val result = decrypter.decrypt(data)

        //then
        assertEquals(
            """{"k1":"v1","k2":"v2","k3":{"k4":"true","k5":["v5","v5"]},"k6":{"k7":{"k8":"72F3E2BBAE18C1D2F4710D4ABBBDFA48F31589"}}}""",
            result
        )
    }

    @Test
    fun `Decrypt raw`() {
        //given
        val decrypter = Decrypter(
            sodium,
            mapOf("$" to "80ACD97A9FA49A16BCE645981A7AB0E13FFE07D1E95BBF6BBFB9DD2DB081ECF5")
        )
        val data = "38F106C87D8C6C259EC39ABFB65B6F79EBD5C0C1F3D1689B"

        //when
        val result = decrypter.decrypt(data)

        //then
        assertEquals("raw data", result)
    }
}
