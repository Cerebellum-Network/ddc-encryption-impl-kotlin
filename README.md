# DDC Encryption Module Kotlin implementation

[![Release](https://jitpack.io/v/cerebellum-network/ddc-encryption-impl-kotlin.svg)](https://jitpack.io/#cerebellum-network/ddc-encryption-impl-kotlin)
[![codecov](https://codecov.io/gh/Cerebellum-Network/ddc-encryption-impl-kotlin/branch/main/graph/badge.svg?token=G73EO1DQLN)](https://codecov.io/gh/Cerebellum-Network/ddc-encryption-impl-kotlin)

Kotlin implementation of DDC crypto functions.

## Requirements

This library requires Java version 11 or higher and Kotlin version 1.4 or higher.

## Usage

Add dependency in your Gradle build script:

```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}
dependencies {
    implementation("com.github.cerebellum-network:ddc-encryption-impl-kotlin:1.5.0")
}
```

```kotlin
// Generating keypair for app
val appKeyPair =
    signingKeyPairFromMnemonic("south foam acquire regular clarify candy crumble burst strong admit bag pig")

assertEquals("0x7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3", appKeyPair.publicKey.toHex())
assertEquals(
    "0xd1c60ff157b5d80df830fde62ea1156dc1905d2efa29a57c3e0a0fb09b16e4cf7f9866baf46bbb2aa60a79c8e1e706d5e6ad83b05b4d3bc18cb7163ab20208c3",
    appKeyPair.privateKey.toHex()
)

// Generating keypair for Alice
val aliceKeyPair =
    signingKeyPairFromMnemonic("spy dune course spatial surface correct appear stable behave impulse banner more")

assertEquals(
    "0x6ba00539acdc05ea4ef40b899cd2fbbb07e76026ac921b40d90ebc0c1c5be6bd",
    aliceKeyPair.publicKey.toHex()
)
assertEquals(
    "0x9f5bf29d5ead8a61bbc7ceee5cafc0b794bc82673a3cccb7f204a80988561f136ba00539acdc05ea4ef40b899cd2fbbb07e76026ac921b40d90ebc0c1c5be6bd",
    aliceKeyPair.privateKey.toHex()
)

// Generating keypair for Bob
val bobKeyPair =
    signingKeyPairFromMnemonic("kitten cover trouble cross advance palace expand talent food approve dumb sound")

assertEquals("0x1e1ce0d657aa3fe22f6d4023264a0f136f7a81c5a6c37fc504ca55fa8e54fe34", bobKeyPair.publicKey.toHex())
assertEquals(
    "0x9c6753406fa0062fa36b664fbf4a2602ead3575ca066bde47454b1bdb7fba8a61e1ce0d657aa3fe22f6d4023264a0f136f7a81c5a6c37fc504ca55fa8e54fe34",
    bobKeyPair.privateKey.toHex()
)

// Encrypting data
val appMasterEncryptionKey = CryptoSecretKey("super-secret".toByteArray())
val aliceData = "raw data"

val encryptedDataWithDek = appMasterEncryptionKey.encryptWithScopes(aliceData)
val encryptedData = encryptedDataWithDek.encryptedData
val dek = encryptedDataWithDek.scopedCryptoSecretKeys.pathToDecryptToDecryptionKeyHex.getValue(JSON_ROOT_PATH)
assertEquals("0x0a5bf15c177ef4facbc154746b55d3d1ee89cfc5f2e05b7b", encryptedData)
assertEquals("0x18bbe83a52beab7a8dc17287613bfdebfe76128c69fa64a6c878515570b26816", dek)

// Sign encrypted data
val signature = appKeyPair.signToHex(encryptedDataWithDek.encryptedData)
assertEquals(
    "0x493f449ea2870319e06d84b3873919c6bedb9041efc2def96a5356d3dc15ba0540847920329122ae4502ce4b99afd8112e982e5698d99a3790299947300a270a",
    signature
)

// ... store in DDC

// Sharing encryption key with Alice and Bob
// Converting app keypair
val appBoxKeyPair = appKeyPair.toCryptoKeyPair()
assertEquals(
    "0x60275679ff8e45a5bba4d1efcc559ce0ca97e4b5baf75631a72e6c29d024557a",
    appBoxKeyPair.privateKey.toHex()
)
assertEquals(
    "0x64758e6d0c0eec66086475c32b85fe8335e99459cc0b2aaae0d43b134b34a104",
    appBoxKeyPair.publicKey.toHex()
)

// Converting Alice keypair
val aliceBoxKeyPair = aliceKeyPair.toCryptoKeyPair()
assertEquals(
    "0xe853d9996c3fa4ccc3f9b896024a0f41e38b65c16ac7f87156157819d1f6c678",
    aliceBoxKeyPair.privateKey.toHex()
)
assertEquals(
    "0x267aad76b826b90752aaae5f6a1c6e11022d96ef448d11b6ba0e573cb1abc775",
    aliceBoxKeyPair.publicKey.toHex()
)

// Converting Bob keypair
val bobBoxKeyPair = bobKeyPair.toCryptoKeyPair()
assertEquals(
    "0x9034d017db4acafee5d9799d9754b0f81f7c2512eb668b3710882a73608b936a",
    bobBoxKeyPair.privateKey.toHex()
)
assertEquals(
    "0x3ccbcca1add841e90b7103fa447ea672df661014206c15de70c5998f93bd9b49",
    bobBoxKeyPair.publicKey.toHex()
)

// Generating key encryption key (KEK) for Alice
val aliceKek = appBoxKeyPair.privateKey.sealFor(dek, aliceBoxKeyPair.publicKey)
assertEquals(
    "0x3ff3a05fa1545c7ec34aca55bd8200704bc569ee0fa575cfc994319b46b9e2510d47a3ad942d1b7cd513ed52301cbd1fc3aeb74a2c0f8525f558a2b329fb6e8cf9e4660455616b98206f5af4ab18d3e374d8",
    aliceKek
)

// Generating key encryption key (KEK) for Bob
val bobKek = appBoxKeyPair.privateKey.sealFor(dek, bobBoxKeyPair.publicKey)
assertEquals(
    "0x706c63b0af761ff407b3ac34991731916d12e5303b778e9ad4e1e11820b5c5b06b609ad346fa6291b1e22555928ae3072ef7086730bdf5cc27d070c761be7f7bfda0727831108fe63b0b55671161cf324c29",
    bobKek
)

// Restoring data using Alice keypair
// Restoring DEK from KEK with Alice private key
val aliceDek = aliceBoxKeyPair.privateKey.openFrom(appBoxKeyPair.publicKey, aliceKek)
assertEquals(dek, aliceDek)

// Decrypting data with DEK
val aliceDecrypted = CryptoSecretKey(aliceDek).decryptDirectly(encryptedData)
assertEquals(aliceData, aliceDecrypted)

// Restoring data using Bob keypair
// Restoring DEK from KEK with Bob private key
val bobDek = bobBoxKeyPair.privateKey.openFrom(appBoxKeyPair.publicKey, bobKek)
assertEquals(dek, bobDek)

// Decrypting data with DEK
val bobDecrypted = CryptoSecretKey(bobDek).decryptDirectly(encryptedData)
assertEquals(aliceData, bobDecrypted)

// Restoring data using app master key
val decryptedData = appMasterEncryptionKey.decryptWithScopes(encryptedData)
assertEquals(aliceData, decryptedData)
```

