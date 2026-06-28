FROM eclipse-temurin:17-jdk AS build
WORKDIR /workspace
COPY . .
RUN ./gradlew :orchestrator:installDist --no-daemon

# Bake a pinned android.jar so the parser's symbol solver can resolve framework calls
# (WebView.loadUrl, Intent.getStringExtra) without a host Android SDK mount. Source:
# github.com/Sable/android-platforms. The server compose points SAST_ANDROID_JAR here;
# the image itself does NOT set SAST_ANDROID_JAR so the dev compose's host-SDK mount still wins.
FROM eclipse-temurin:17-jre AS android-jar
ARG ANDROID_API=34
RUN set -eux; \
    apt-get update; apt-get install -y --no-install-recommends curl ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /opt/android/android-${ANDROID_API}; \
    curl -fsSL -o /opt/android/android-${ANDROID_API}/android.jar \
      "https://raw.githubusercontent.com/Sable/android-platforms/master/android-${ANDROID_API}/android.jar"

FROM eclipse-temurin:17-jre
ARG ANDROID_API=34
WORKDIR /workspace
COPY --from=build /workspace/orchestrator/build/install/orchestrator /opt/orchestrator
COPY --from=android-jar /opt/android /opt/android
ENV TEMPORAL_ADDRESS=temporal:7233
ENV ARTIFACT_ROOT=/workspace/artifacts
ENTRYPOINT ["/opt/orchestrator/bin/orchestrator"]
