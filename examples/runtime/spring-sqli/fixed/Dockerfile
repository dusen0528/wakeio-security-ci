FROM docker.io/library/maven@sha256:2060a0028047a1974e7e0e343f93b7d2742db8cce69cb5662cf2a9a09b17dbca AS build
WORKDIR /tmp
ENV HOME=/tmp
COPY --chown=65532:65532 pom.xml ./pom.xml
COPY --chown=65532:65532 src ./src
USER 65532:65532
RUN mvn --batch-mode --no-transfer-progress -Dmaven.repo.local=/tmp/wakeio-m2 verify
FROM docker.io/library/eclipse-temurin@sha256:57424b1d8eca9c4cf8a4fe226207027911f08d6758628891bf59fcfb53777029
WORKDIR /app
COPY --from=build --chown=65532:65532 /tmp/target/primary-sqli-1.0.0.jar /app/app.jar
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
