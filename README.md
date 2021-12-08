# BTPN Service

## Dependency :
1. install java 1.8 update 80 keatas
2. install maven 
3. POSTGRESS untuk database
4. create database dengan nama monitoring
5. untuk pertama kali pastikan sebelum running di file \src\main\resources\application.properties user dan password sudah sesuai dengan database

## Cara compile :
1. mvn clean
2. mvn package > juga akan menghasilkan file .jar di folder target

## Cara run via Jar :
1. java -jar container-monitoring-0.0.2-SNAPSHOT.jar 

## Cara run :
1. mvn spring-boot:run

## cara deploy ke docker (create docker image)
1. docker build -t container-monitoring:0.0.2-SNAPSHOT .

## cara jalanin image docker (Bind ke port 8080)
1. docker run --name web-container -p 8080:8080 -d container-monitoring:0.0.2-SNAPSHOT
