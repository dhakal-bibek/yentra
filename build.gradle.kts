plugins {
    java
}

group = "io.sw33tlie.burp"
// Version comes from -Pversion= passed by the release workflow (derived from the git tag).
// Local builds fall back to a snapshot so the jar name is still meaningful.
version = (project.findProperty("version") as String?)?.takeIf { it.isNotBlank() && it != "unspecified" }
    ?: "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-serial"))
}

tasks.jar {
    archiveBaseName.set("yentra")
    manifest {
        attributes(
            "Implementation-Title" to "Yentra",
            "Implementation-Version" to project.version
        )
    }
}
