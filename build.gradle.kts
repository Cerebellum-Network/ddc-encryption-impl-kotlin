import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.32"
    maven
    jacoco
}

group = "com.github.cerebellum-network"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))

    // Crypto
    implementation("org.purejava:tweetnacl-java:1.1.2")
    implementation("com.rfksystems:blake2b:1.0.0")
    implementation("commons-codec:commons-codec:1.15")
    implementation("cash.z.ecc.android:kotlin-bip39:1.0.2")

    // JSON
    implementation("com.github.jsurfer:jsurfer-jackson:1.6.0")
    implementation("com.jayway.jsonpath:json-path:2.5.0")

    // Tests
    testImplementation(platform("org.junit:junit-bom:5.7.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = JavaVersion.VERSION_11.toString()
            javaParameters = true
        }
    }

    withType<Test> {
        useJUnitPlatform()
        finalizedBy(jacocoTestReport)
    }

    withType<JacocoReport> {
        reports {
            xml.isEnabled = true
            html.isEnabled = false
        }
    }
}
