# How to Install the OpenID4JavaAuthModule #

The OpenID4JavaAuthModule I have written is easy to install. To enable your JEE Web application for OpenID you need a Server plattform supporting JSR-196. The following section will describe the installation steps for a Glassfish Application Server. Glassfish supports JSR-196. But there may be also other web containers supporting JSR-196.

To install the OpenID4Java AuthModule you first need to download the following parts:

  * [imixs-openid-0.0.3](http://code.google.com/p/openid4java-jsr196/downloads/list)
> > Includes my new JSR-196 ServerAuthModule implementation based on the openid4java library.
  * [openid4java-0.9.5.jar](http://code.google.com/p/openid4java/downloads/list)
> > Includes the official openid4java library and additional tools provided by the OpenID4Java Group.

Copy the imixs-openid-0.0.2-SNAPSHOT.jar into the Glassfish Lib folder

`[GLASSFISHHOME]/lib/`

Extract the the openid4java zip archive and copy the following jars into your Glassfish Domain lib/ext/ folder.

  * openid4java-0.9.5.jar
  * commons-codec-1.3.jar
  * commons-httpclient-3.0.1.jar
  * commons-logging-1.03.jar

The glassfish domain specific /lib folder is located on the following path:

`[GLASSFISHHOME]/domains/domain1/lib/ext/`

where domain1 is your prefered domain (domain1 is the default domain typical used).

Notice: The three commons-