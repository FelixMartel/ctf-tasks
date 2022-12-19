FROM tomcat:10.1.2

RUN useradd --uid 1001 --shell /bin/bash tomcat

COPY index.jsp /usr/local/tomcat/webapps/ROOT/index.jsp
COPY web.xml /usr/local/tomcat/webapps.dist/ROOT/WEB-INF/web.xml
COPY flag /flag

RUN cd lib && wget https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/8.0.31/mysql-connector-j-8.0.31.jar \
     && wget https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/3.1.0/mariadb-java-client-3.1.0.jar \
     && wget https://repo1.maven.org/maven2/com/microsoft/sqlserver/mssql-jdbc/11.2.1.jre17/mssql-jdbc-11.2.1.jre17.jar \
     && wget https://repo1.maven.org/maven2/com/ibm/db2/jcc/db2jcc/db2jcc4/db2jcc-db2jcc4.jar \
     && wget https://search.maven.org/remotecontent?filepath=com/h2database/h2/2.1.214/h2-2.1.214.jar  

USER 1001
EXPOSE 8080
CMD ["/usr/local/tomcat/bin/catalina.sh", "run"] 
