package network.cere.ddc.crypto.v1.key.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class CryptoPrivateKeyTest {
    private val ourPrivateKey = CryptoPrivateKey("0x60275679ff8e45a5bba4d1efcc559ce0ca97e4b5baf75631a72e6c29d024557a")
    private val ourPublicKey = CryptoPublicKey("0x64758e6d0c0eec66086475c32b85fe8335e99459cc0b2aaae0d43b134b34a104")
    private val theirPrivateKey = CryptoPrivateKey("0x9034d017db4acafee5d9799d9754b0f81f7c2512eb668b3710882a73608b936a")
    private val theirPublicKey = CryptoPublicKey("0x3ccbcca1add841e90b7103fa447ea672df661014206c15de70c5998f93bd9b49")

    @Test
    fun `Seal for`() {
        //given
        val message = "super secret message to be shared"

        //when
        val sealed = ourPrivateKey.sealFor(message, theirPublicKey)

        //then
        assertEquals(
            "0xc112cac5ed2aede19cb49b671e4c86902e1fa46d2b3598c784f2b15e62bdc1a12f60c5d205bf3a83ebb03317c989f7062f",
            sealed
        )
    }

    @Test
    fun `Open from`() {
        //given
        val sealedHex =
            "0xc112cac5ed2aede19cb49b671e4c86902e1fa46d2b3598c784f2b15e62bdc1a12f60c5d205bf3a83ebb03317c989f7062f"

        //when
        val original = theirPrivateKey.openFrom(ourPublicKey, sealedHex)

        //then
        assertEquals("super secret message to be shared", original)
    }
}
