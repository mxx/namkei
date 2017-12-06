FROM java:8-alpine
MAINTAINER Your Name <you@example.com>

ADD target/uberjar/namkei.jar /namkei/app.jar

EXPOSE 3000

CMD ["java", "-jar", "/namkei/app.jar"]
