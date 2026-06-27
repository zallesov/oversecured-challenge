FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace
COPY . .
RUN ./gradlew :orchestrator:installDist --no-daemon

FROM eclipse-temurin:17-jre
WORKDIR /workspace
COPY --from=build /workspace/orchestrator/build/install/orchestrator /opt/orchestrator
ENV TEMPORAL_ADDRESS=temporal:7233
ENV ARTIFACT_ROOT=/workspace/artifacts
ENTRYPOINT ["/opt/orchestrator/bin/orchestrator"]
