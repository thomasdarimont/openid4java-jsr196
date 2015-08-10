# Configuration of the OpenID4JavaAuthModule #

After you have [installed](http://code.google.com/p/openid4java-jsr196/wiki/HowToInstall) the module in you web server you can configure the OpenID4JavaAuthModule. The following example shows the configuration using the GlassFish Server. (Pleas note that there are some different UI between Glassfish 2.1 and the latest Glasfish 3.1 server version. But the concepts are identically. If you have any suggestions about the configuration please post them into the [issue list](http://code.google.com/p/openid4java-jsr196/issues/list).)


  1. Make sure the GlassFish Application Server is running. If it is not already running, you can start it using the following command:
> > `<GF_HOME>bin/asadmin start-domain domain1`
> > where `<GF_HOME>` is the directory where you installed GlassFish


> 2. Open the GlassFish Admin Console by pointing your browser to the URL: http://localhost:4848/.

> 3. Login to the Admin Console by entering your ID and password.

> 4. Expand the Configuration node at the bottom of the left-hand pane.

> 5. Navigate to the Security node, expand it, and click MessageSecurity.

![http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish1.png](http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish1.png)


> 6. Under Message Security Configurations, either open the HttpServlet layer if it already exists, or create it if it doesn't exist by clicking the New button. Clicking the button opens the New Message Security Configuration window.

> If you can not see the HttpServlet node you need to create the layer:

> Click the "New" button and you can than start to configure the new provider in one step. To do that:
    * Set the following in the New Message Security Configuration window:

> Provider Type: server
> Provider ID: OpenIDProvider
> Class Name: org.imixs.openid.openid4java.OpenID4JavaAuthModule

> Do not check the Default Provider: Enabled check box.


  * Click the OK button. This saves the settings and opens the Message Security Configurations window.
  * Click on HttpServlet in the Authentication Layer column.
  * Select the Providers tab. This opens the Provider Configuration window.
  * Select OpenIDProvider in the Provider ID column you just created. This opens the Edit Provider Configuration window.
  * Click the Save button to complete the configuration of the provider.

> If the HttpServlet layer already exists, you open first the provider list and add a new Provider:
    * Open the HttpServlet layer by selecting it in the Message Security Configurations window.
    * Select the Providers tab to open the Provider Configuration window.

![http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish3.png](http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish3.png)


  * Click the New button to open the New Provider Configuration window.
  * In the Provider Configuration area of the window, set the following:

> Provider Type: server
> Provider ID: OpenIDProvider
> Class Name: org.imixs.openid.openid4java.OpenID4JavaAuthModule

> Do not check the Default Provider: Enabled check box.

For the first configuration this is a little bit confusing as you need to create the HttpServlet Layer. But in general the hole configuration is very simple.

Also note that the provider configuration utility also provides a dialog box that you can use to configure additional properties. We will use this properties to configure out OpenIDProvider for our applications.

# Configure additional Properties #

After adding the new OpenIDProvider like described before you can start using the provider in your web application. But there a also a few additional properties which can be configured for each provider instance. You can add these properties by using the box "additional properties at the end of you configuration page:

![http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish4.png](http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/glassfish4.png)


The different properties and there usage are described below:

## assign.groups ##

This property is the most important one. It defines which group will be assigned to a user how has logged on with his OpenID. Typical this is a default group used in your web application.
## debug.stages ##

This property allows you define different debug stages. So you can follow the different phases during the logon process on the server log. Remove this property to turn the debug modus off to switch off debugging.

## loginpage ##

Per default the login module will prompt the user with a simple login page where he can enter his OpenID. You can replace this default page with a individual page supported by your web application (similar to a form based authentication). I will discus this later.

(The other params - verfiymode and debug - shown in the screenshot are deprecated and can be left)


# Configuration of your Web Application #

Now I will explain how you can configure your web application to use openid as a login mechanism. If you have installed the OpenID Login module like described before this step is quiet easy.
web.xml & sun-web.xml

The first thing what you should do is remove existing tag login-config like basic or form-based authentification configuration from the web.xml if available. Using JSR-196 you now only need the security-constraint configuration.

This is an example of the security-constraint seciton in my web.xml

```
....
	<security-constraint>
		<display-name>Access Manager Security Constraint</display-name>
		<web-resource-collection>
			<web-resource-name>AUTHENTICATED_RESOURCE
			</web-resource-name>
			<url-pattern>/pages/*</url-pattern>
		</web-resource-collection>
		<auth-constraint>
			<role-name>org.imixs.ACCESSLEVEL.AUTHORACCESS
			</role-name>
		</auth-constraint>
	</security-constraint>
	
	<security-role>
		<role-name>org.imixs.ACCESSLEVEL.AUTHORACCESS
		</role-name>
	</security-role>
.....
```

Next you need to link your openid provider configured on glassfish admin client with you web application in the sun-web.xml.

Therefor you need to add the attriubte "httpservlet-security-provider" with the name of your openid provider. The the following example of my sun-web.xml file:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE sun-web-app PUBLIC "-//Sun Microsystems, Inc.//DTD Application Server 9.0 Servlet 2.5//EN" "http://www.sun.com/software/appserver/dtds/sun-web-app_2_5-0.dtd">
<sun-web-app error-url="" httpservlet-security-provider="OpenIDProvider">

	<context-root>/openidtestclient</context-root>

	<security-role-mapping>
		<role-name>org.imixs.ACCESSLEVEL.AUTHORACCESS</role-name>
		<group-name>Author</group-name>
	</security-role-mapping>

	<class-loader delegate="true" />
	<jsp-config>
		<property name="keepgenerated" value="true">
			<description>Keep a copy of the generated servlet class java
				code.</description>
		</property>
	</jsp-config>
</sun-web-app> 
```

That's it!

Now You will see a default login page if you try to login to your web application:

![http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/openid_page1.gif](http://www-02.imixs.com/roller/ralphsjavablog/resource/openid/openid_page1.gif)

## Role Mapping ##

Notice that we mapped also our default group "Author" to a application specific role name. The group "Author" was configured in the OpenIDProvider property "assign.groups". So each user how have successful authenticated against his OpenID Provider will default to this group and the role  "org.imixs.ACCESSLEVEL.AUTHORACCESS". You can change this settings to the requirements of your application.