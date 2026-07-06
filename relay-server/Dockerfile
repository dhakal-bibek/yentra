FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /build
COPY build.gradle.kts settings.gradle* gradlew ./
COPY gradle/ gradle/
RUN ./gradlew --version
COPY src/ src/
RUN ./gradlew build -x test

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /build/build/libs/burp-dedupe-*.jar burp-dedupe.jar
EXPOSE 8080
ENTRYPOINT ["java", "-cp", "burp-dedupe.jar", "burpdedupe.liveshare.RelayServer", "8080"]
