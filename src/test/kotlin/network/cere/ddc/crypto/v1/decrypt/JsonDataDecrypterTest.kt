package network.cere.ddc.crypto.v1.decrypt

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class JsonDataDecrypterTest {
    @Test
    fun `Decrypt JSON`() {
        //given
        val config = DecryptionConfig(
            mapOf(
                "$.k1" to "0ae19ba1e42a63aefea507a19df00ffc962bc894b3fb720723d45e456f636977",
                "$.k3.k4" to "fd6dc3ab97230e17e75266493ebae617556f83d83851f1a8f061629dbd7c08ef"
            )
        )
        val decrypter = JsonDataDecrypter(config)
        val data = """
            {
                "k1": "0fa7e2cc912228f89df09b783ec3e9114fbafd2a5836f692392793eb6ec3db133b9b62ef9b3539defcd7",
                "k2": "v2",
                "k3": {
                    "k4": "49be07e70fb439e3bd19d1307dce5e8e32cca231065955b869e0c521a2043b2f93a0f9195ff606a989115002",
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": "2e98a7462fe1017b65de4104abd29ff2e10c6782e8ab6cc44e96766cfe31e08650b6f45ea7ca3e7fc7b671"
                    }
                }
            }
        """.trimIndent().toByteArray()

        //when
        val result = decrypter.decrypt(data)

        //then
        assertEquals(
            """{"k1":"v1","k2":"v2","k3":{"k4":"true","k5":["v5","v5"]},"k6":{"k7":{"k8":"2e98a7462fe1017b65de4104abd29ff2e10c6782e8ab6cc44e96766cfe31e08650b6f45ea7ca3e7fc7b671"}}}""",
            result.decodeToString()
        )
    }
}
