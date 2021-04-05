# DDC Encryption Module Kotlin implementation

[![Release](https://jitpack.io/v/cerebellum-network/ddc-encryption-impl-kotlin.svg)](https://jitpack.io/#cerebellum-network/ddc-encryption-impl-kotlin)

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
    implementation("com.github.cerebellum-network:ddc-encryption-impl-kotlin:1.+")
}
```

## API

### V1

#### Sign the message

```kotlin
val privateKeyHex = "0xcafebabe"
val msg = "to be signed"

//with Ed25519 schema
val ed25519Signer: Signer = Ed25519Signer(Hex.decode(privateKeyHex))
val ed25519Signature = ed25519Signer.signToBytes(msg)

//with Sr25519 schema
val sr25519Signer: Signer = Sr25519Signer(Hex.decode(privateKeyHex))
val sr25519Signature = sr25519Signer.signToBytes(msg)
```

#### Encrypt and decrypt raw message

```kotlin
val data = "raw data".toByteArray()
val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())
val encrypter = Encrypter(EncryptionConfig(masterKeyHex, TypeHint.RAW))
val decrypter = Decrypter(
    DecryptionConfig(
        TypeHint.RAW,
        mapOf("" to masterKeyHex)
    )
)
val encrypted = encrypter.encrypt(data)
val decrypted = decrypted.decrypt(result) // "raw data"
```

#### Encrypt and decrypt JSON message

```kotlin
//given
val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())
val encrypter = Encrypter(
    EncryptionConfig(
        masterKeyHex,
        TypeHint.JSON,
        listOf("$.k1") // JSON Paths we want to encrypt, default is "$..*" which means all fields
    )
)
val decrypter = Decrypter(
    DecryptionConfig(
        TypeHint.JSON,
        mapOf("$.k1" to "0ae19ba1e42a63aefea507a19df00ffc962bc894b3fb720723d45e456f636977") // derived key for this path
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

val encrypted = encrypter.encrypt(data)
val decrypted = decrypted.decrypt(result) // "original json"
```


