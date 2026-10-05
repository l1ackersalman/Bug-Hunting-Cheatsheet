# Table of Contents
1. [API Types](#api-types)
2. [API Reconnaissance](#api-reconnaissance)
   - 2.1. [Discovering API Documentation](#discovering-api-documentation)
   - 2.2.  [Discovering Api Technology](#Discovering-Api-Technology)
   - 2.3. [Fuzzing](#fuzzing)
   - 2.4. [Burp Scanner](#burp-scanner)
   - 2.5. [Changing HTTP Methods](#changing-http-methods)
3. [Mass Assignment](#mass-assignment)
4. [Testing for Server-Side Parameter Pollution (SSPP)](#testing-for-server-side-parameter-pollution-sspp)
   - 4.1. [Testing the Query String 🔴](#testing-the-query-string)
   - 4.2. [Testing in REST Paths 🔴](#testing-in-rest-paths)
   - 4.3. [Overriding Existing Parameters](#overriding-existing-parameters)
   - 4.4. [Testing in REST Paths](#testing-in-rest-paths)
   - 4.5. [Testing in Structured Data Formats](#testing-in-structured-data-formats)
5. [Examples and Techniques](#examples-and-techniques)
   - 5.1. [Truncating Query Strings](#truncating-query-strings)
   - 5.2. [Injecting Invalid Parameters](#injecting-invalid-parameters)
   - 5.3. [Injecting Valid Parameters](#injecting-valid-parameters)
6. [Special Cases](#special-cases)
   - 6.1. [Structured Data Formats (JSON, XML)](#structured-data-formats-json-xml)

---

**Related Topic:** [Server-Side-Parameter-Pollution](https://github.com/tasin-zucced/Bug-Hunting-Cheatsheet/blob/main/Server%20Side%20Parameter%20Pollution.md)

---

# API Types

## ✅ 1. **REST API**
- **Method-based on HTTP verbs**

### 🔸 Request
```http
GET /users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>
```

### 🔸 Response
```json
{
  "id": 123,
  "username": "tasin",
  "email": "tasin@example.com"
}
```

🧠 **Data Flow**: 
- Request hits `/users/123`
- Server fetches data for user `123`
- JSON sent as response

---

## ✅ 2. **GraphQL API**
- **All requests go to a single endpoint (`/graphql`)**

### 🔸 Request (POST)
```http
POST /graphql HTTP/1.1
Content-Type: application/json

{
  "query": "{ user(id: 123) { username email } }"
}
```

### 🔸 Response
```json
{
  "data": {
    "user": {
      "username": "tasin",
      "email": "tasin@example.com"
    }
  }
}
```

🧠 **Data Flow**:
- Client defines what fields they want
- Server resolves the requested fields
- Only requested data is returned

---

## ✅ 3. **gRPC API** (binary protocol over HTTP/2)

### 🔸 `.proto` definition
```proto
service UserService {
  rpc GetUser(UserRequest) returns (UserResponse);
}

message UserRequest {
  int32 id = 1;
}

message UserResponse {
  string username = 1;
  string email = 2;
}
```

🧠 **Data Flow**:
- Client sends binary-encoded request
- Server processes it using defined proto
- Returns binary-encoded response

> Use `grpcurl` to test or intercept.

---

## ✅ 4. **SOAP API**
- **Uses XML + WSDL**

### 🔸 Request
```http
POST /userService HTTP/1.1
Content-Type: text/xml

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Body>
      <getUser>
         <id>123</id>
      </getUser>
   </soapenv:Body>
</soapenv:Envelope>
```

### 🔸 Response
```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
   <soap:Body>
      <getUserResponse>
         <username>tasin</username>
         <email>tasin@example.com</email>
      </getUserResponse>
   </soap:Body>
</soap:Envelope>
```

🧠 **Data Flow**:
- XML request processed by the server
- XML response returned

---

## ✅ 5. **WebSocket API**
- **For real-time data flow**

### 🔸 Handshake (Initial Upgrade Request)
```http
GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
```

✅ If accepted, connection upgrades to full-duplex

### 🔸 Data Example (JSON over WebSocket)
```json
{ "action": "sendMessage", "to": "tasin", "msg": "Yo!" }
```

🧠 **Data Flow**:
- Once connected, both client & server can push/pull data anytime

---

## ✅ 6. **JSON-RPC API**

### 🔸 Request
```http
POST /api HTTP/1.1
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "method": "getUser",
  "params": { "id": 123 },
  "id": 1
}
```

### 🔸 Response
```json
{
  "jsonrpc": "2.0",
  "result": {
    "username": "tasin",
    "email": "tasin@example.com"
  },
  "id": 1
}
```

🧠 **Data Flow**:
- JSON-RPC defines a consistent message format for request/response
- Useful for remote procedure call APIs

---

## ✅ 7. **SSE (Server-Sent Events)**

### 🔸 Request
```http
GET /events HTTP/1.1
Accept: text/event-stream
```

### 🔸 Response (streaming)
```
data: { "message": "Hello Tasin!" }
```

🧠 **Data Flow**:
- Server pushes events to browser one-way
- Great for live stock data, alerts, etc.

---

## ✅ 8. **OData API**

### 🔸 Request
```http
GET /users?$filter=id eq 123 HTTP/1.1
Host: api.example.com
```

### 🔸 Response
```json
{
  "value": [
    {
      "id": 123,
      "username": "tasin",
      "email": "tasin@example.com"
    }
  ]
}
```

🧠 **Data Flow**:
- Data filtering is done by query options (`$filter`, `$select`, `$orderby`, etc.)

---

## ✅ 9. **AsyncAPI (event-based, e.g., MQTT, Kafka)**

### 🔸 Example (MQTT publish)
```bash
# Publish message
mosquitto_pub -h broker.example.com -t user/123/alert -m '{"message": "New login"}'
```

🧠 **Data Flow**:
- Publish-subscribe model
- Data is pushed to all subscribers of a topic

---

# API Reconnaissance

### 1.1. Discovering API Documentation
- Identify potential API documentation endpoints such as `/api-docs`, `/swagger`, `/openapi`, etc.
- Use automated tools or wordlists to fuzz for common API paths.
- Check for exposed API documentation, like OpenAPI or Swagger files such as `/api`, `/swagger/index.html`, `/openapi.json`, which can reveal endpoints, parameters, and authentication details.

### 1.2. Discovering Api Technology
**Java / Spring (springfox & springdoc)**
- `/swagger-ui.html`
- `/swagger-ui/`, `/swagger-ui/index.html`
- `/v2/api-docs` (springfox, older)
- `/v3/api-docs` (springdoc, newer — Spring Boot 2.6+/3.x)
- `/v3/api-docs/swagger-config`

**Python — FastAPI**
- `/docs` (Swagger UI, default)
- `/redoc` (ReDoc, default)
- `/openapi.json`

**Python — Flask (flask-swagger / flasgger / connexion)**
- `/apidocs/`, `/apidocs/index.html` (flasgger default)
- `/swagger.json`
- `/api/swagger.json`

**Node.js — Express (swagger-jsdoc / swagger-ui-express)**
- `/api-docs` (very common custom mount point)
- `/docs`
- `/swagger.json`

**.NET / ASP.NET Core (Swashbuckle)**
- `/swagger`
- `/swagger/index.html`
- `/swagger/v1/swagger.json`

**Ruby (rswag)**
- `/api-docs`
- `/swagger_doc.json`

**Go (swaggo)**
- `/swagger/index.html`
- `/swagger/doc.json`

**Generic / framework-agnostic — worth hitting regardless of stack**
- `/openapi.json`, `/openapi.yaml`, `/openapi.yml`
- `/api/openapi.json`
- `/.well-known/openapi.json` (rare, but check)
- `/api/v1/swagger.json`, `/api/v2/swagger.json` (version-prefix variants)
- `/redoc.html`

### 1.3. Fuzzing
- Use wordlists based on common API naming conventions and industry-specific terms.
- Tools like Burp Suite, OWASP ZAP, or ffuf can help discover hidden or undocumented endpoints.
```
swagger
swagger.json
swagger.yaml
swagger.yml
swagger-ui
swagger-ui.html
swagger-ui/
swagger-ui/index.html
swagger/
swagger/index.html
swagger/ui
swagger/ui/index.html
swagger-resources
swagger-resources/configuration/ui
swagger-resources/configuration/security
openapi.json
openapi.yaml
openapi.yml
openapi
api-docs
api-docs.json
api-docs/
api/docs
api/swagger.json
api/swagger.yaml
api/openapi.json
api/api-docs
docs
docs/
redoc
redoc.html
redoc/
rapidoc
rapidoc.html
v1/swagger.json
v1/api-docs
v1/openapi.json
v2/api-docs
v2/swagger.json
v2/openapi.json
v3/api-docs
v3/api-docs/swagger-config
v3/swagger.json
v3/openapi.json
api/v1/swagger.json
api/v1/openapi.json
api/v1/docs
api/v1/api-docs
api/v2/swagger.json
api/v2/openapi.json
api/v2/docs
api/v2/api-docs
api/v3/swagger.json
api/v3/openapi.json
api/v3/docs
swagger-ui.html
v2/api-docs
v3/api-docs
v3/api-docs/swagger-config
webjars/springfox-swagger-ui/springfox.js
swagger-resources/configuration/ui
swagger-resources/configuration/security
docs
redoc
openapi.json
apidocs
apidocs/
apidocs/index.html
flasgger_static/swagger-ui.css
swagger.json
api/swagger.json
spec
spec.json
api-docs
api-docs/
docs
swagger.json
api/docs
api/swagger.json
swagger
swagger/index.html
swagger/v1/swagger.json
swagger/v1/swagger.yaml
index.html
swagger/ui/index
api-docs
api-docs/
api-docs.json
swagger_doc.json
swagger_doc/v1/swagger.json
swagger/index.html
swagger/doc.json
swagger/swagger.json
docs/swagger.json
docs/swagger.yaml
api/documentation
docs/api
swagger/docs
storage/api-docs/api-docs.json
graphql
graphiql
playground
graphql/console
altair
voyager
postman.json
postman_collection.json
insomnia.json
.well-known/openapi.json
.well-known/swagger.json
.well-known/schema.json
schema
schema.json
schema.yaml
spec/swagger.json
spec/openapi.json
static/swagger.json
static/openapi.json
assets/swagger.json
public/swagger.json
dist/swagger.json
internal-docs
dev-docs
api-explorer
api-console
api-reference
developer
developers
developer/docs
```

### 1.4. Burp Scanner
- Configure Burp Suite to perform automated vulnerability scans on API endpoints.
- Customize scan configurations to focus on specific vulnerabilities, such as authentication issues or sensitive data exposure.

### 1.5. Changing HTTP Methods
- Test different HTTP methods (GET, POST, PUT, DELETE, etc.) on the same endpoint.
- Check if changing the method alters the response or bypasses certain access controls.

---

# Mass Assignment

Mass assignment vulnerabilities occur when an application blindly accepts user input and sets multiple attributes on an object without validation. Attackers can exploit this to manipulate parameters or escalate privileges.

**Example Attack Scenario:**
A web app allows users to update their profile with fields like `name`, `email`.
```json
{
    "name": "Alice",
    "email": "alice@example.com",
}
```
If the server does not validate the incoming data. An attacker could add the `"isAdmin": true` field, thereby escalating privileges if the application does not restrict this.
```json
{
    "name": "Alice",
    "email": "alice@example.com",
    "isAdmin": true
}
```

---

# Testing for Server-Side Parameter Pollution (SSPP)

### 4.1. Testing the Query String
### URL-Encoded `&` and `#`

When testing **SSPP**, encode query delimiters and check whether the server decodes them and interprets them as part of a **second/internal request**.

#### `%26` → `&` — Inject a parameter

```text
username=administrator%26x=y
```

After decoding:

```text
username=administrator&x=y
```

If used in an internal request:

```text
/internal-api?username=administrator&x=y
```

`x=y` becomes a **new parameter**.

**Indicator:** An error like `Parameter is not supported` may confirm that the injected parameter reached the internal API.

#### `%23` → `#` — Truncate the query

```text
username=administrator%23
```

After decoding:

```text
username=administrator#
```

If the server builds:

```text
/internal-api?username=administrator#&field=test
```

`#` starts the fragment, so `field=test` is no longer part of the query.

**Indicator:** An error such as `Field not specified` may suggest that `field` was removed from the internal request.

#### Combine Both

```text
username=administrator%26field=x%23
```

Decoded:

```text
username=administrator&field=x#
```

This attempts to **inject `field=x` and then truncate the remaining query**.

**Remember:**

```text
%26 → &
%23 → #
```

The interesting behavior occurs when the application **decodes your input and uses it to construct another server-side URL/query**.

[![Watch Video](https://img.youtube.com/vi/JMsZ6eg3nkU/maxresdefault.jpg)](https://www.youtube.com/watch?v=JMsZ6eg3nkU)

### 4.2. Testing in REST Paths

Test whether user input is inserted into a **server-side URL path**.

#### `#` / `?` — Detect Path Injection

```text
username=administrator%23
username=administrator%3F
```

➡️ `#` and `?` can truncate the URL path.

**Indicator:** `Invalid route`

---

#### `./` and `../` — Path Traversal

```text
username=./administrator
username=../administrator
```

➡️ `./` may access the same path, while `../` moves up one directory.

**Indicator:** Different response or `Invalid route`

---

#### Discover API Definition

Use traversal to reach the API root:

```text
username=../../../../%23
```

Then test API definition files:

```text
username=../../../../openapi.json%23
```

➡️ May reveal internal endpoints such as:

```text
/api/internal/v1/users/{username}/field/{field}
```

---

#### Inject Valid Path Parameters

Use the discovered endpoint structure:

```text
username=administrator/field/email%23
```

➡️ Test whether `email` is accepted as the `field` value.

---

#### API Version Manipulation

If another API version exists, try changing the version:

```text
username=../../v1/users/administrator/field/passwordResetToken%23
```

➡️ May access parameters or functionality unavailable in the application's normal API version.

**Key idea:** User input → server-side URL path → path manipulation → internal API discovery/manipulation.

### 4.3. Overriding Existing Parameters
- Try injecting duplicate parameters to see which one the server processes:
   ```
   name=attacker&name=originalUser
   ```
- The server's behavior varies by technology:
   - **PHP/Apache:** Uses the last parameter.
   - **ASP.NET:** Concatenates the parameters.
   - **Node.js/Express/Apache Tomcat:** Uses the first parameter.
     
### 4.4. Testing in REST Paths
- Test RESTful APIs by manipulating URL path parameters.
- Use path traversal sequences:
   ```
   /users/carlos/../../../../../
   ```
- Fuzz for common API definition files:
   ```
   /../../../../openapi.json
   ```

### 4.5. Testing in Structured Data Formats
- Test requests containing structured data formats (e.g., JSON, XML).
- Inject parameters directly into JSON requests:
   ```json
   {
       "name": "bob",
       "access_level": "administrator"
   }
   ```

---

# Examples and Techniques

### 5.1. Truncating Query Strings
- Use the `#` character to attempt truncation:
   ```
   http://example.com/resource?param=value%23additional
   ```

### 5.2. Injecting Invalid Parameters
- Add an unexpected or invalid parameter:
   ```
   &invalidParam=unexpectedValue
   ```

### 5.3. Injecting Valid Parameters
- Add a known, valid parameter to observe how it is processed:
   ```
   name=attacker&email=attacker@example.com
   ```

---

# Special Cases

### 6.1. Structured Data Formats (JSON, XML)
- **JSON Example:** Modify an API request that uses JSON:
   ```json
   POST /myaccount
   {
       "name": "john",
       "role": "admin"
   }
   ```
- **XML Example:** Manipulate XML data for injection:
   ```xml
   <user>
       <name>john</name>
       <role>admin</role>
   </user>
   ```
- Structured data injection can be leveraged in request or response data.

---
