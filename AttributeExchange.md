# OpenID Attriubte Exchange #

Since Version 0.0.5 openid4java-jsr196 is now supporting the [OpenID attribute exchange](http://openid.net/specs/openid-attribute-exchange-1_0.html).

To consume attributes from the OpenID provider the additional configuration option named "attribute.exchange" can be used.
This param expects a list of attriubte/schema combinations for the requested attributes.

The expected format is:

> attribute|shema,attriubte|shema,....

For example:

> email|http://schema.openid.net/contact/email,fullname|http://schema.openid.net/namePerson=fullname

This option exhanges the attributes: email and fullname.

The values received from the OpenID Provider are provided by a map object which is stored the user session by the key 'openid.attriubte\_exchange'