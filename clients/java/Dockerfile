# Java client: Eclipse Temurin (current LTS) with default JSSE, or Bouncy Castle JSSE
# first when PQCC_PROVIDER=bc (the java-bc client). Build context: ./clients
FROM eclipse-temurin:25-jdk@sha256:63f965b560b905c9633218330ac3516304b526a74fdc323a504b05c06e712c30

ADD --checksum=sha256:2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f \
    https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar /app/lib/
ADD --checksum=sha256:1c268e15f785aafb1e4670d8d6e5f856f69475e96c162dadcd1ff9b350e9139f \
    https://repo1.maven.org/maven2/org/bouncycastle/bcutil-jdk18on/1.86/bcutil-jdk18on-1.86.jar /app/lib/
ADD --checksum=sha256:8ce8d5fb1b5d323a73df1fdba920b2f97c12d047986028fe65bf64d3997e50f2 \
    https://repo1.maven.org/maven2/org/bouncycastle/bctls-jdk18on/1.86.2/bctls-jdk18on-1.86.2.jar /app/lib/

COPY java/Client.java /app/
RUN javac -cp '/app/lib/*' -d /app /app/Client.java

# PQCC_JAVA_OPTS: extra JVM flags (used by java-bc-pq to enable ML-DSA signature schemes).
RUN printf '#!/bin/sh\nexec java $PQCC_JAVA_OPTS -cp "/app:/app/lib/*" Client "$@"\n' > /usr/local/bin/pqcc-client \
 && chmod 755 /usr/local/bin/pqcc-client
