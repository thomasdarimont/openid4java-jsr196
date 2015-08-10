**Adding HTTP Proxy support to OpenID4Java JSR 196 SAM Module**

When your glassfish server needed to access the web via a proxy you can add an additional proxy configuration.


To use this, simply add the following "additional properties" to the HttpServlet security provider:

  * http\_proxy\_host (ex. "proxy.example.com", required)
  * http\_proxy\_port (ex. "8080", optional, defaults to null)
  * http\_proxy\_user (ex. "myusername", optional, defaults to null)
  * http\_proxy\_pass (optional, defaults to null)



See also details here:
http://nuttybrewer.blogspot.com/2010/05/adding-http-proxy-support-to.html