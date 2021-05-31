package network.cere.ddc.crypto.v1.key.sign

import network.cere.ddc.crypto.v1.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class MnemonicKtTest {
    @Test
    fun `Generate keypair from mnemonic 1`() {
        //given
        val mnemonic = "south foam acquire regular clarify candy crumble burst strong admit bag pig"

        //when
        val keyPair = signingKeyPairFromMnemonic(mnemonic)

        //then
        assertEquals(
            "0xd1c60ff157b5d80df830fde62ea1156dc1905d2efa29a57c3e0a0fb09b16e4cf7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3",
            keyPair.privateKey.toHex()
        )
        assertEquals(
            "0x7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3",
            keyPair.publicKey.toHex()
        )
    }

    @Test
    fun `Generate keypair from mnemonic 2`() {
        //given
        val mnemonic = "spy dune course spatial surface correct appear stable behave impulse banner more"

        //when
        val keyPair = signingKeyPairFromMnemonic(mnemonic)

        //then
        assertEquals(
            "0x9f5bf29d5ead8a61bbc7ceee5cafc0b794bc82673a3cccb7f204a80988561f136ba00539acdc05ea4ef40b899cd2fbbb07e76026ac921b40d90ebc0c1c5be6bd",
            keyPair.privateKey.toHex()
        )
        assertEquals(
            "0x6ba00539acdc05ea4ef40b899cd2fbbb07e76026ac921b40d90ebc0c1c5be6bd",
            keyPair.publicKey.toHex()
        )
    }

    @Test
    fun `Generate keypair from mnemonic 3`() {
        //given
        val mnemonic = "kitten cover trouble cross advance palace expand talent food approve dumb sound"

        //when
        val keyPair = signingKeyPairFromMnemonic(mnemonic)

        //then
        assertEquals(
            "0x9c6753406fa0062fa36b664fbf4a2602ead3575ca066bde47454b1bdb7fba8a61e1ce0d657aa3fe22f6d4023264a0f136f7a81c5a6c37fc504ca55fa8e54fe34",
            keyPair.privateKey.toHex()
        )
        assertEquals(
            "0x1e1ce0d657aa3fe22f6d4023264a0f136f7a81c5a6c37fc504ca55fa8e54fe34",
            keyPair.publicKey.toHex()
        )
    }
}
