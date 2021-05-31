package network.cere.ddc.crypto.v1.key.sign

import network.cere.ddc.crypto.v1.toHex
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class SigningPublicKeyTest {
    @Test
    fun `Verify valid signature`() {
        //given
        val message = "some message"
        val signature =
            "0x11f0ebeb4d66bd173d6576cab9208c4129c1746adf806ed248badf230be6b826ebbc45ca0c1bf4add833b4c12d821279806d94bb97074777ff8e805d14b7bb01"
        val key = SigningPublicKey("0x7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3")

        //when
        val isValid = key.isValidSignature(message, signature)

        //then
        assertTrue(isValid)
    }

    @Test
    fun `Verify invalid signature`() {
        //given
        val message = "some message"
        val signature =
            "0x21f0ebeb4d66bd173d6576cab9208c4129c1746adf806ed248badf230be6b826ebbc45ca0c1bf4add833b4c12d821279806d94bb97074777ff8e805d14b7bb01"
        val key = SigningPublicKey("0x7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3")

        //when
        val isValid = key.isValidSignature(message, signature)

        assertFalse(isValid)
    }

    @Test
    fun `Convert to crypto public key`() {
        //given
        val key = SigningPublicKey("0x7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3")

        //when
        val cryptoPublicKey = key.toCryptoPublicKey()

        //then
        assertEquals(
            "0x64758e6d0c0eec66086475c32b85fe8335e99459cc0b2aaae0d43b134b34a104",
            cryptoPublicKey.toHex()
        )
    }
}
