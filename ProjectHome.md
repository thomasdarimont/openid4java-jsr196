# OpenID4Java JSR 196 SAM Module #

This Open Source Project provides a ServerAuthModule based on JSR-196 to authenticate users with an OpenID account. You can run this module to authenticate users in your own web application through the internet using OpenID authentication. The openid4java-jsr196 library can be used with Glassfish 2.1 or higher, or any other Web- or Application server supporting the JSR-196 standard.

This project makes use of the OpenID4Java library. [OpenID4Java](http://code.google.com/p/openid4java/) is a open source library supporting the Client side authentication process to login a user with an OpenID.

## What is OpenID? ##
OpenID is an open standard that allows a User to sign into web sites through a single URL (a single digital identity). This URL can be a personal home page, a blog or a web service (e.g from a OpenID Provider like [https://www.myopenid.com/}, [https://www.google.com/accounts Google](myopenid.md) or [yahoo.com](http://developer.yahoo.com/openid/)) that the user is already using. In any case the user must register only once with his OpenID service provider and therefore he need only one password. Another advantage of using OpenID in your web application is the exemption of hosting and managing user accounts and password informations. You can read more about the details on [openid.net](http://openid.net/).

## OpenID and JSR-196 ##
There are different solutions available to enable a Web Application to login users with there OpenID account. One of the most auspicious mechanisms to integrate OpenID in JEE Applications is the [jsr-196](http://www.jcp.org/en/jsr/detail?id=196). This authentication service allows web containers to use different login modules - like an external openid provider. JSR-196 is part of the JEE6 specification. Running your web application with Glassfish Server it is very easy to use a JSR-196 authentication module. Ron Monzillo who was specification lead gives a good overview about the jsr-192 on his blog:  [concepts behind JRS-196](http://blogs.sun.com/enterprisetechtips/entry/adding_authentication_mechanisms_to_the).

You are welcome to join this project! Please post comments or suggestion into the [IssueList](http://code.google.com/p/openid4java-jsr196/issues/list).


  * [How to Install the OpenID4JavaAuthModule](http://code.google.com/p/openid4java-jsr196/wiki/HowToInstall?ts=1308431559&updated=HowToInstall)
  * [Configuration](http://code.google.com/p/openid4java-jsr196/wiki/Configuration)
  * [Proxy Support](http://code.google.com/p/openid4java-jsr196/wiki/HTTPProxySupport)
  * [Attribute Exchange](http://code.google.com/p/openid4java-jsr196/wiki/AttributeExchange)

## Downlaod & Support ##

You can download the lates version form the [Donwload List](http://code.google.com/p/openid4java-jsr196/downloads/list).

For further support you can contact me at [imixs.com](http://www.imixs.com) or [imixs.org](http://www.imixs.org)

See also details about OpenID4Java at: http://code.google.com/p/openid4java/