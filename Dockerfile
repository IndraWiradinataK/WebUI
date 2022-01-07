FROM registry.access.redhat.com/ubi8/openjdk-8-runtime
ARG JAR_FILE=target/*.jar
ARG KEYSTORE_SSL_FILE=target/classes/cert/keystore.p12
ARG KEYSTORE_FILE=target/classes/cert/keystore.jks
ARG TRUSTSTORE_FILE=target/classes/cert/truststore.jks
ENV ENV_WEBUI_ANCHORE_URL=https://anchore-engine-consec-dev.apps.cluster-d2a5.sandbox944.opentlc.com/v1/
ENV ENV_WEBUI_ANCHORE_USER=admin
ENV ENV_WEBUI_ANCHORE_PASS=foobar
ENV ENV_WEBUI_FALCO_URL=http://falco-endpoint-consec-dev.apps.cluster-d2a5.sandbox944.opentlc.com/api/
ENV ENV_WEBUI_FALCO_USER=itg_falco
ENV ENV_WEBUI_FALCO_PASS=SuperPassword123!@#
ENV ENV_DB_URL=jdbc:postgresql://localhost:5432/monitoring
ENV ENV_DB_USER=postgres
ENV ENV_DB_PASS=secret
ENV ENV_LDAP_URL=ldap://localhost:10389/
ENV ENV_LDAP_BASE=ou=people,dc=example,dc=com
ENV ENV_LDAP_USER=uid=admin,ou="people test",dc=example,dc=com
ENV ENV_LDAP_PASS=xYN9C5@SP#5xbeqn
ENV ENV_LDAP_BASE_DN=ou=people,dc=example,dc=com
ENV ENV_LDAP_BASE_DN_FIL_1=uid={0}
ENV ENV_LDAP_BASE_DN_FIL_2=uid
ENV ENV_DASH_KIBANA=https://172.104.162.117:5601/goto/892f773ed3781d2e21624ebe1e449d7d
EXPOSE 8080
COPY ${JAR_FILE} /usr/app/monitoring.jar
COPY ${KEYSTORE_SSL_FILE} /home/jboss/keystore.p12
COPY ${KEYSTORE_FILE} /usr/app/keystore.jks
COPY ${TRUSTSTORE_FILE} /usr/app/truststore.jks
ENTRYPOINT ["java","-jar","/usr/app/monitoring.jar"]