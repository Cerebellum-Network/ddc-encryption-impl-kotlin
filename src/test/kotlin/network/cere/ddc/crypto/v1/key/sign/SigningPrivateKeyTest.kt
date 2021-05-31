package network.cere.ddc.crypto.v1.key.sign

import network.cere.ddc.crypto.v1.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class SigningPrivateKeyTest {
    @Test
    fun `Sign message`() {
        //given
        val message = "some message"
        val key =
            SigningPrivateKey("0xd1c60ff157b5d80df830fde62ea1156dc1905d2efa29a57c3e0a0fb09b16e4cf7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3")

        //when
        val signature = key.signToHex(message)

        //then
        assertEquals(
            "0x11f0ebeb4d66bd173d6576cab9208c4129c1746adf806ed248badf230be6b826ebbc45ca0c1bf4add833b4c12d821279806d94bb97074777ff8e805d14b7bb01",
            signature
        )
    }

    @Test
    fun `Convert to crypto private key`() {
        //given
        val key =
            SigningPrivateKey("0xd1c60ff157b5d80df830fde62ea1156dc1905d2efa29a57c3e0a0fb09b16e4cf7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3")

        //when
        val cryptoPrivateKey = key.toCryptoPrivateKey()

        //then
        assertEquals(
            "0x60275679ff8e45a5bba4d1efcc559ce0ca97e4b5baf75631a72e6c29d024557a",
            cryptoPrivateKey.toHex()
        )
    }
}
