FROM eclipse-temurin:21-jre

WORKDIR /app

COPY build/libs/ctink-0.0.1-SNAPSHOT.jar /app/app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]