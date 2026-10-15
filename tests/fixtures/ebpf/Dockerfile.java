# Java fixture for Rule R6: two jars on the classpath, only one ever used.
#
# Mirrors the Python fixture's requests-vs-tabulate shape. Both jars are present
# and both are on the classpath, so only *runtime* evidence can tell them apart —
# the JVM resolves com.example.used.Greeter on first active use and never touches
# com.example.unused.Idle. Built entirely from source so the image needs no
# network at build time and the jar coordinates are deterministic.
FROM eclipse-temurin:21-jdk

WORKDIR /build
RUN mkdir -p src/com/example/used src/com/example/unused /libs /app && \
    printf 'package com.example.used;\npublic class Greeter { public static String hi() { return "hi"; } }\n' \
      > src/com/example/used/Greeter.java && \
    printf 'package com.example.unused;\npublic class Idle { public static String no() { return "no"; } }\n' \
      > src/com/example/unused/Idle.java && \
    javac -d cu src/com/example/used/Greeter.java && \
    javac -d cn src/com/example/unused/Idle.java && \
    jar cf /libs/usedlib-1.0.jar -C cu . && \
    jar cf /libs/unusedlib-1.0.jar -C cn .

RUN printf 'public class App { public static void main(String[] a) { System.out.println(com.example.used.Greeter.hi()); } }\n' \
      > /app/App.java && \
    javac -cp /libs/usedlib-1.0.jar -d /app /app/App.java

# Run with:  java -cp /libs/usedlib-1.0.jar:/libs/unusedlib-1.0.jar:/app App
CMD ["sleep", "600"]
