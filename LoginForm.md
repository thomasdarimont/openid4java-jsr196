# Using a custom Login Form #

If you did not specific a login form with the additional property "loginpage" the OpenID Login Module will answer an unautenticated request with an simple login form as shown above.

You can implement you own login form if you like and use this form as the default form for your openidProvider module.

There for add the property "loginpage"  to your provider configuration and support a valid Page inside your application or a simple HTTP page located on a web server.

This is a simple example for a individual login form based on JSF :

```
	<form method="get"
		action="#{facesContext.externalContext.requestContextPath}/openid_login">
		<f:facet name="header">
			<h:outputLabel value="#{global.login_title} " />
		</f:facet>
		<h:panelGrid columns="2">
			<h:outputLabel value="#{global.username}:" />
			<h:inputText id="openid_identifier" />

			<h:inputHidden id="return_to"
				value="#{loginMB.serverURI}#{facesContext.externalContext.requestContextPath}/pages/notes.jsf" />

		</h:panelGrid>
		<input type="submit" value="#{global.login}" />


		<!-- BEGIN ID SELECTOR -->
		<script type="text/javascript" id="__openidselector"
			src="https://www.idselector.com/selector/e0ed3a269b77fa785de90aeaa20fa0f985746767"
			charset="utf-8"></script>
		<!-- END ID SELECTOR -->
		<script type="text/javascript">
			var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
			document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));
			</script>
						<script type="text/javascript">
			var pageTracker = _gat._getTracker("UA-3469303-6");
			pageTracker._trackPageview();
		</script>
	</form>
```

Your form need to care about three things:

  1. The form action method need to point to the method path "/openid\_login". This path indicates the OpenIDLogin Module to start an OpenID Login process.
> 2. The users Input field to enter his OpenID URL should be named "openid\_identifier". Make sure that the "name" and "ID" attribute are set to "openid\_identifier"
> 3. The form must support a hidden field "return\_to" with points to a page where the user is redirected after login process succeed.



The ID Selector Script is just a funny script provided by http://www.idselector.com to support the user with a nice widget to simplify using openid.