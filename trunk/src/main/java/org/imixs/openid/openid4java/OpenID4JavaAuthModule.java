/*******************************************************************************
 *  Imixs Workflow Technology
 *  Copyright (C) 2010 Imixs Software Solutions GmbH, Ralph Soika  
 *  http://www.imixs.org
 *  
 *  This program is free software; you can redistribute it and/or 
 *  modify it under the terms of the GNU General Public License 
 *  as published by the Free Software Foundation; either version 2 
 *  of the License, or (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, 
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 *  General Public License for more details.
 *  
 *  You can receive a copy of the GNU General Public
 *  License at http://www.gnu.org/licenses/gpl.html
 *  
 *  Contributors:  
 *  	Ralph Soika
 *******************************************************************************/

package org.imixs.openid.openid4java;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;

/**
 * This Class is a JSR-196 based ServerAuthModul using OpenID4Java to
 * authenticate users against OpenID Providers.
 * 
 * The Class depends on the following apache libraries:
 * <ul>
 * <li>- commons-codec-1.3.jar
 * <li>- commons-httpclient-3.0.1.jar
 * <li>- commons-logging-1.03.jar
 * <p>
 *  
 * and also the openid4java lib: openid4java-full-0.9.5.jar
 * 
 * @author rsoika
 */
public class OpenID4JavaAuthModule implements ServerAuthModule {


	private static final String loginAction = "openid_login";
	private static final String loginURI = "/" + loginAction;

	private static final int DEBUG_TRACE = 1;
	private static final int DEBUG_LOGIN_FORM = 2;
	private static final int DEBUG_ASSOCIATION = 4;
	private static final int DEBUG_JMAC = 8;
	private static final HashMap debugStagesMap = new HashMap();
	static {
		debugStagesMap.put("all", DEBUG_TRACE + DEBUG_LOGIN_FORM
				+ DEBUG_ASSOCIATION + DEBUG_JMAC);
		debugStagesMap.put("trace", DEBUG_TRACE);
		debugStagesMap.put("form", DEBUG_LOGIN_FORM);
		debugStagesMap.put("association", DEBUG_ASSOCIATION);
		debugStagesMap.put("jmac", DEBUG_JMAC);

	}
	private int debugStagesMask;

	protected static final Class[] supportedMessageTypes = new Class[] {
			javax.servlet.http.HttpServletRequest.class,
			javax.servlet.http.HttpServletResponse.class };

	protected final Logger logger = Logger
			.getLogger(OpenID4JavaAuthModule.class.getName());
	protected Map options;
	protected CallbackHandler handler;
	protected MessagePolicy requestPolicy;
	protected MessagePolicy responsePolicy;

	private static final String IS_MANDATORY_INFO_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";
	private static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
	protected static final String ASSIGN_GROUPS_OPTIONS_KEY = "assign.groups";
	private static String DEBUG_STAGES_OPTIONS_KEY = "debug.stages";
	public static final String OPENID_IDENTIFIER = "openid.identifier";
	public static final String OPENID_CONSUMER_MANAGER = "openid.consumer_manager";
	protected static final String SAVED_REQUEST_ATTRIBUTE = "javax.security.auth.message.SavedHttpRequest";

	protected String[] assignedGroups;
	protected boolean isMandatory;

	/**
	 * Module specific options as configured in options Map
	 * 
	 * openid.session_type=sessionType
	 * 
	 * openid.content.type = contenttype value set in Accept header of identity
	 * page request.
	 * 
	 * 
	 * debug-stages=all or subset {trace,form,idpage,association,checkid,trust}
	 * trace - log trace of the message processing form - log login form
	 * processing association - log openid association processing checkid - log
	 * check id processing trust - trusted server evaluation all - log all of
	 * the above.
	 * 
	 * shared options:
	 * 
	 * 
	 * assign.groups=groupList shared groups added as a side-effect of
	 * authentication.
	 * 
	 */
	public void initialize(MessagePolicy requestPolicy,
			MessagePolicy responsePolicy, CallbackHandler handler, Map options)
			throws AuthException {

		this.requestPolicy = requestPolicy;
		this.responsePolicy = responsePolicy;
		this.isMandatory = requestPolicy.isMandatory();
		this.handler = handler;
		this.options = options;
		this.assignedGroups = parseAssignGroupsOption(options);

		debugStagesMask = parseDebugStagesOption(options);

	}

	/**
	 * Get the one or more Class objects representing the message types
	 * supported by the module.
	 * 
	 * @return An array of Class objects, with at least one element defining a
	 *         message type supported by the module.
	 */
	public Class[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}

	/**
	 * Authenticate a received service request. This method conveys the outcome
	 * of its message processing either by returning an AuthStatus value or by
	 * throwing an AuthException.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param clientSubject
	 *            A Subject that represents the source of the service request.
	 *            It is used by the method implementation to store Principals
	 *            and credentials validated in the request.
	 * 
	 * @param serviceSubject
	 *            A Subject that represents the recipient of the service
	 *            request, or null.
	 * 
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 * 
	 *         <ul>
	 *         <li>AuthStatus.SUCCESS when the application request message was
	 *         successfully validated.
	 * 
	 *         <li>AuthStatus.SEND_SUCCESS to indicate that
	 *         validation/processing of the request message successfully
	 *         produced the secured application response message (in
	 *         messageInfo). The secured response message is available by
	 *         calling getResponseMessage on messageInfo.
	 * 
	 *         <li>AuthStatus.SEND_CONTINUE to indicate that message validation
	 *         is incomplete, and that a preliminary response was returned as
	 *         the response message in messageInfo.
	 * 
	 *         When this status value is returned to challenge an application
	 *         request message, the challenged request must be saved by the
	 *         authentication module such that it can be recovered when the
	 *         module's validateRequest message is called to process the request
	 *         returned for the challenge.
	 * 
	 *         <li>AuthStatus.SEND_FAILURE to indicate that message validation
	 *         failed and that an appropriate failure response message is
	 *         available by calling getResponseMessage on messageInfo.
	 *         </ul>
	 * 
	 * @exception AuthException
	 *                When the message processing failed without establishing a
	 *                failure response message (in messageInfo).
	 */
	public AuthStatus validateRequest(MessageInfo messageInfo,
			Subject clientSubject, Subject serviceSubject) throws AuthException {

		assert (messageInfo.getMap().containsKey(IS_MANDATORY_INFO_KEY) == isMandatory);

		HttpServletRequest request = (HttpServletRequest) messageInfo
				.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo
				.getResponseMessage();

		// is it a response from an OpenID Login page?
		// than process the authentification against the OpenID Provider...
		if (isRequestURILogin(request)) {
			logInfo(DEBUG_TRACE, "openid.received_login_form");

			String userSuppliedString = getQueryParameter(request,
					"openid_identifier");

			logInfo(DEBUG_TRACE, "openid.userSupplied_id=" + userSuppliedString);

			String returnToUrl = getQueryParameter(request, "return_to");

			logInfo(DEBUG_TRACE, "openid.return_to=" + returnToUrl);
			
			// calling openid4java manager
			authentificate(messageInfo, userSuppliedString, returnToUrl);

			logInfo(DEBUG_TRACE, "openid.do_request_continued");

			return AuthStatus.SEND_CONTINUE;

		} else {
			/*
			 * Test if we have still an OPENID_IDENTIFIER
			 */
			Identifier identifier = getOpenIDIdentifier(messageInfo);

			// do we have an token?
			if (identifier == null) {
				// No!
				logInfo(DEBUG_TRACE, "openid.cleanup_session");
				request.getSession().removeAttribute(
						OPENID_CONSUMER_MANAGER);
				request.getSession().removeAttribute(OPENID_IDENTIFIER);
				request.getSession().removeAttribute("openid-disc");

				
				// If the request is protected than response with an openID
				// login form
				if (isMandatory) {
					logInfo(DEBUG_TRACE, "openid.respond_with_login_page");
					respondWithLoginForm(request, response);
				} else {
					// the request is not protected so simple succeed the
					// request...
					return AuthStatus.SUCCESS;
				}
			} else {
				// We still have a valid token
				// so we can set the caller pricipal now

				String id = identifier.getIdentifier();
				setCallerPrincipal(id, clientSubject);
				messageInfo.getMap().put(AUTH_TYPE_INFO_KEY, "OpenID");
				return AuthStatus.SUCCESS;
			}
		}
		return AuthStatus.SEND_CONTINUE;
	}

	/**
	 * Remove method specific principals and credentials from the subject.
	 * 
	 * @param messageInfo
	 *            a contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param subject
	 *            the Subject instance from which the Principals and credentials
	 *            are to be removed.
	 * 
	 * @exception AuthException
	 *                If an error occurs during the Subject processing.
	 */
	public void cleanSubject(MessageInfo messageInfo, Subject subject)
			throws AuthException {
		if (subject != null) {
			logInfo(DEBUG_TRACE, "openid.do_clean_subject");
			subject.getPrincipals().clear();
		}
	}

	/**
	 * Secure a service response before sending it to the client.
	 * 
	 * This method is called to transform the response message acquired by
	 * calling getResponseMessage (on messageInfo) into the mechanism-specific
	 * form to be sent by the runtime.
	 * <p>
	 * This method conveys the outcome of its message processing either by
	 * returning an AuthStatus value or by throwing an AuthException.
	 * 
	 * @param messageInfo
	 *            A contextual object that encapsulates the client request and
	 *            server response objects, and that may be used to save state
	 *            across a sequence of calls made to the methods of this
	 *            interface for the purpose of completing a secure message
	 *            exchange.
	 * 
	 * @param serviceSubject
	 *            A Subject that represents the source of the service response,
	 *            or null. It may be used by the method implementation to
	 *            retrieve Principals and credentials necessary to secure the
	 *            response. If the Subject is not null, the method
	 *            implementation may add additional Principals or credentials
	 *            (pertaining to the source of the service response) to the
	 *            Subject.
	 * 
	 * @return An AuthStatus object representing the completion status of the
	 *         processing performed by the method. The AuthStatus values that
	 *         may be returned by this method are defined as follows:
	 * 
	 *         <ul>
	 *         <li> AuthStatus.SEND_SUCCESS when the application response
	 *         message was successfully secured. The secured response message
	 *         may be obtained by calling getResponseMessage on messageInfo.
	 * 
	 *         <li> AuthStatus.SEND_CONTINUE to indicate that the application
	 *         response message (within messageInfo) was replaced with a
	 *         security message that should elicit a security-specific response
	 *         (in the form of a request) from the peer.
	 * 
	 *         This status value serves to inform the calling runtime that (to
	 *         successfully complete the message exchange) it will need to be
	 *         capable of continuing the message dialog by processing at least
	 *         one additional request/response exchange (after having sent the
	 *         response message returned in messageInfo).
	 * 
	 *         When this status value is returned, the application response must
	 *         be saved by the authentication module such that it can be
	 *         recovered when the module's validateRequest message is called to
	 *         process the elicited response.
	 * 
	 *         <li> AuthStatus.SEND_FAILURE to indicate that a failure occurred
	 *         while securing the response message and that an appropriate
	 *         failure response message is available by calling
	 *         getResponseMeessage on messageInfo.
	 *         </ul>
	 * 
	 * @exception AuthException
	 *                When the message processing failed without establishing a
	 *                failure response message (in messageInfo).
	 * 
	 * @author this method was initial implemented by monzillo
	 */
	public AuthStatus secureResponse(MessageInfo messageInfo,
			Subject serviceSubject) throws AuthException {

		boolean wrapped = false;
		HttpServletRequest r = (HttpServletRequest) messageInfo
				.getRequestMessage();
		while (r != null && r instanceof HttpServletRequestWrapper) {
			r = (HttpServletRequest) ((HttpServletRequestWrapper) r)
					.getRequest();
			wrapped = true;
		}
		if (wrapped) {
			messageInfo.setRequestMessage(r);
		}
		wrapped = false;
		HttpServletResponse s = (HttpServletResponse) messageInfo
				.getResponseMessage();
		while (s != null && s instanceof HttpServletResponseWrapper) {
			s = (HttpServletResponse) ((HttpServletResponseWrapper) s)
					.getResponse();
			wrapped = true;
		}
		if (wrapped) {
			messageInfo.setResponseMessage(s);
		}

		return AuthStatus.SEND_SUCCESS;
	}

	/**
	 * This method verifies if the current session holds an validated identifier
	 * object. If not the method tries to get a new one by calling the
	 * verifyResponse method
	 * 
	 * @param request
	 * @return
	 */
	public Identifier getOpenIDIdentifier(MessageInfo messageInfo) {

		HttpServletRequest request = (HttpServletRequest) messageInfo
				.getRequestMessage();

		Identifier identifier = (Identifier) request.getSession().getAttribute(
				OPENID_IDENTIFIER);
		// no identifier available? - so try to generate a new one form the
		// current request....
		if (identifier == null) {
			identifier = verifyResponse(messageInfo);
			if (identifier != null) {
				// put verified identifier....
				request.getSession()
						.setAttribute(OPENID_IDENTIFIER, identifier);

				// now we can finally remove the consumer manager as
				// authenification is completed....
				logInfo(DEBUG_TRACE, "openid.remove_consumer_manager");
				request.getSession().removeAttribute(OPENID_CONSUMER_MANAGER);
			}
		}

		return identifier;

	}



	/**
	 * This method returns a shared ConsumerManager instance. If no instance is
	 * still available the method creates a new ConsumerManager and stores the
	 * consumer Manager in the session.
	 * 
	 * @param request
	 * @return
	 */
	private ConsumerManager getConsumerManager(HttpServletRequest request) {
		ConsumerManager manager = (ConsumerManager) request.getSession()
				.getAttribute(OPENID_CONSUMER_MANAGER);
		if (manager == null) {
			// instantiate a ConsumerManager object
			try {
				logInfo(DEBUG_TRACE, "openid.createing_consumer_manager");
				manager = new ConsumerManager();
				manager.getRealmVerifier().setEnforceRpId(false);
				// store shared consumer_manager
				request.getSession().setAttribute(OPENID_CONSUMER_MANAGER,
						manager);

			} catch (ConsumerException e) {
				e.printStackTrace();

			}
		}
		return manager;
	}

	private boolean checkLogCriteria(int criteria) {
		return (criteria != 0 && ((debugStagesMask & criteria) == criteria));
	}

	private void logInfo(int criteria, String tag) {
		if (checkLogCriteria(criteria)) {
			logger.log(Level.INFO, tag);
		}
	}

	private void logInfo(int criteria, String tag, String msg) {
		if (checkLogCriteria(criteria)) {
			// logger.log(Level.INFO, tag, msg);
			logger.log(Level.INFO, tag + ": " + msg);
		}
	}

	private static int parseDebugStagesOption(Map options) {
		int bitMap = 0;
		if (options != null) {
			String option = ((String) options.get(DEBUG_STAGES_OPTIONS_KEY));
			if (option != null) {
				StringTokenizer tokenizer = new StringTokenizer(option, ",");
				while (tokenizer.hasMoreTokens()) {
					String token = tokenizer.nextToken();
					Integer value = (Integer) debugStagesMap.get(token);
					if (value != null)
						bitMap += value.intValue();
				}
			}
		}
		return bitMap;
	}

	/**
	 * This method indicates if the httpReqeust include openid login params. The
	 * method verifies two cases. 1. check if the requesUI ends tith the /
	 * 
	 * 2.check if the url contains the params 'openid_identifier' and
	 * 'return_to'
	 * 
	 * @param request
	 * @return
	 */
	private boolean isRequestURILogin(HttpServletRequest request) {
		String uri = request.getRequestURI();
		if (uri == null)
			return false;

		// is it a response from an OpenID Login page?
		if (uri.endsWith(loginURI))
			return true;

		// test if the URL contains the openid params 'openid_identifier' and
		// 'return_to'
		String userSuppliedString = getQueryParameter(request,
				"openid_identifier");
		String returnToUrl = getQueryParameter(request, "return_to");
		if ((userSuppliedString != null && !"".equals(userSuppliedString))
				&& (returnToUrl != null && !"".equals(returnToUrl)))
			return true;

		return false;
	}

	/**
	 * Generate OpenID login form and write to response. It might be good to
	 * also include the Glassfish logo, although if we do that we will need to
	 * make sure it can be turned off via the module options. NB: we are only
	 * saving in respond_to the parts of the initial request that appear to be
	 * permitted (in respond_to) by openid 1.0. we have also saved the entire
	 * request in the session.
	 * 
	 * @param request
	 * @param response
	 * @throws javax.security.auth.message.AuthException
	 */

	private void respondWithLoginForm(HttpServletRequest request,
			HttpServletResponse response) throws AuthException {
		try {

			String loginPage = (String) options.get("loginpage");

			if (loginPage != null && !"".equals(loginPage)) {
				// add ReturnTo URL
				// saveRequest(request);
				loginPage += "?return_to=" + makeReturnTo(request);
				// redirect(loginPage, response);
				// return;
				// RequestDispatcher d =
				// request.getRequestDispatcher(loginPage);
				// d.forward(request,response);
				// d.include(request, response);

				PrintWriter writer = response.getWriter();

				response.setContentType("text/html");

				writer.println("<html>");
				writer
						.println("<head><meta http-equiv=\"refresh\" content=\"0; URL="
								+ loginPage + "\" /></head>");
				writer.println("</html>");
				writer.flush();

				logInfo(DEBUG_LOGIN_FORM,
						"openid.responding_with_external_login_form", loginURI);

			} else {
				PrintWriter writer = response.getWriter();

				response.setContentType("text/html");

				writer.println("<html>");
				writer.println("<head></head>");
				writer.println("<br>");
				writer.println("Please Enter OpenID URL\n");
				writer.println("<hr>");
				writer.print("<form action=\"");
				writer.print(loginAction);
				writer.println("\" method=\"get\">");
				writer.println("<img src=\"http://openid.net/login-bg.gif\">");
				writer
						.println("<INPUT TYPE=\"text\" NAME=\"openid_identifier\" VALUE=\"\" SIZE=\"80\">");
				writer.println("<br><br>");
				writer
						.println("<INPUT TYPE=\"submit\" value=\"Login\"> <INPUT TYPE=\"reset\" value=\"Clear\">");
				writer
						.print("<INPUT TYPE=\"hidden\" NAME=\"return_to\" value=\"");
				writer.print(makeReturnTo(request));
				writer.println("\">");

				writer.println("</FORM>");
				writer.println("</html>");
				writer.flush();

				logInfo(DEBUG_LOGIN_FORM, "openid.responding_with_login_form",
						loginURI);
			}
		} catch (Exception e) {
			logger.log(Level.WARNING, "openid.error_writing_login_form");
			AuthException ae = new AuthException();
			ae.initCause(e);
			throw ae;
		}
	}

	private String getQueryParameter(HttpServletRequest request,
			String parameter) {
		String rvalue = null;
		String query = request.getQueryString();
		if (query != null) {

			StringTokenizer tokenizer = new StringTokenizer(query, "&");

			while (tokenizer.hasMoreTokens()) {

				String token = tokenizer.nextToken();

				if (token.startsWith(parameter)) {
					rvalue = token.substring(parameter.length() + 1);
					if (rvalue.length() > 0) {
						try {
							rvalue = URLDecoder.decode(rvalue, "UTF-8");
						} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
							return null;
						}
					}
					break;
				}

			}
		}

		return rvalue;
	}

	private String makeReturnTo(HttpServletRequest request) {
		StringBuffer return_to = request.getRequestURL();

		String queryString = request.getQueryString();
		if (queryString != null) {
			return_to.append("?" + queryString);
		}
		return return_to.toString();
	}

	/**
	 * This method uses the OpenID4Java Manager to authenticate a user with an
	 * provided OpenID
	 * 
	 * @param messageInfo
	 * @return
	 */
	private void authentificate(MessageInfo messageInfo,
			String userSuppliedString, String returnToUrl) {
		try {

			HttpServletRequest request = (HttpServletRequest) messageInfo
					.getRequestMessage();

			HttpServletResponse response = (HttpServletResponse) messageInfo
					.getResponseMessage();

			// perform discovery on the user-supplied identifier
			List discoveries = getConsumerManager(request).discover(
					userSuppliedString);

			// attempt to associate with the OpenID provider
			// and retrieve one service endpoint for authentication
			logInfo(DEBUG_ASSOCIATION, "openid.consumer_manager_associate");

			DiscoveryInformation discovered = getConsumerManager(request)
					.associate(discoveries);

			// store the discovery information in the user's session
			logInfo(DEBUG_ASSOCIATION, "openid.save_openid-disc");
			request.getSession().setAttribute("openid-disc", discovered);
			// obtain a AuthRequest message to be sent to the OpenID
			// provider
			logInfo(DEBUG_ASSOCIATION, "openid.consumer_manager_authenticate");

			AuthRequest authReq = getConsumerManager(request).authenticate(
					discovered, returnToUrl);

			if (!discovered.isVersion2()) {
				// Option 1: GET HTTP-redirect to the OpenID Provider
				// endpoint
				// The only method supported in OpenID 1.x
				// redirect-URL usually limited ~2048 bytes

				// response.sendRedirect(authReq.getDestinationUrl(true));

				// return AuthStatus.SUCCESS;
			} else {
				// Option 2: HTML FORM Redirection (Allows payloads >2048
				// bytes)
				/*
				 * RequestDispatcher dispatcher = request.getServletContext()
				 * .getRequestDispatcher("formredirection.jsp");
				 * request.setAttribute("parameterMap",
				 * authReq.getParameterMap());
				 * request.setAttribute("destinationUrl", authReq
				 * .getDestinationUrl(false)); dispatcher.forward(request,
				 * response);
				 */

			}

			try {
				logInfo(DEBUG_ASSOCIATION, "openid.send_redirect");

				response.sendRedirect(authReq.getDestinationUrl(true));
			} catch (IOException e) {
				e.printStackTrace();
			}

		} catch (OpenIDException e) {
			e.printStackTrace();
		}

	}

	private String[] parseAssignGroupsOption(Map options) {
		String[] groups = new String[0];
		if (options != null) {
			String groupList = (String) options.get(ASSIGN_GROUPS_OPTIONS_KEY);
			if (groupList != null) {
				StringTokenizer tokenizer = new StringTokenizer(groupList,
						" ,:,;");
				Set<String> groupSet = null;
				while (tokenizer.hasMoreTokens()) {
					if (groupSet == null) {
						groupSet = new HashSet<String>();
					}
					groupSet.add(tokenizer.nextToken());
				}
				if (groupSet != null && !groupSet.isEmpty()) {
					groups = groupSet.toArray(groups);
				}
			}
		}
		return groups;
	}

	private boolean setCallerPrincipal(String caller, Subject clientSubject) {
		boolean rvalue = true;
		boolean assignGroups = true;

		// create CallerPrincipalCallback
		CallerPrincipalCallback cPCB = new CallerPrincipalCallback(
				clientSubject, caller);

		if (cPCB.getName() == null && cPCB.getPrincipal() == null) {
			assignGroups = false;
		}

		try {

			handler.handle((assignGroups ? new Callback[] {
					cPCB,
					new GroupPrincipalCallback(cPCB.getSubject(),
							assignedGroups) } : new Callback[] { cPCB }));

			logInfo(DEBUG_JMAC, "jmac.caller_principal:" + cPCB.getName() + " "
					+ cPCB.getPrincipal());

		} catch (Exception e) {
			// should not happen
			logger.log(Level.WARNING, "jmac.failed_to_set_caller", e);
			rvalue = false;
		}

		return rvalue;
	}

	/**
	 * returns teh verified identifier after a succeeded authentication
	 * 
	 * @param request
	 * @return
	 */
	private Identifier verifyResponse(MessageInfo messageInfo) {
		try {
			HttpServletRequest request = (HttpServletRequest) messageInfo
					.getRequestMessage();

			// retrieve the previously stored discovery information
			DiscoveryInformation discovered = (DiscoveryInformation) request
					.getSession().getAttribute("openid-disc");

			// if no discovered available - return null!
			if (discovered == null) {
				// logInfo(DEBUG_ASSOCIATION,
				// "unable to openid.do_verifiy_response - no openid-disc");
				return null;

			}

			logInfo(DEBUG_ASSOCIATION, "openid.do_verifiy_response");
			// extract the parameters from the authentication response
			// (which comes in as a HTTP request from the OpenID provider)
			ParameterList response = new ParameterList(request
					.getParameterMap());

			// extract the receiving URL from the HTTP request
			StringBuffer receivingURL = request.getRequestURL();
			String queryString = request.getQueryString();

			// In some cases the receivingURL did not contain the default port
			// 80 which is necessary for further verifying.
			// So I will add port 80 to the receivingURL if no port
			// is provided here
			try {
				URL urlReceifing = new URL(receivingURL.toString());
				if (urlReceifing.getPort() == -1) {
					// no port! so add port 80!
					urlReceifing = new URL(urlReceifing.getProtocol(),
							urlReceifing.getHost(), 80, urlReceifing.getFile());
					receivingURL = new StringBuffer(urlReceifing.toString());
				}
			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			if (queryString != null && queryString.length() > 0) {
				receivingURL.append("?").append(request.getQueryString());
			}

			// verify the response; ConsumerManager needs to be the same
			// (static) instance used to place the authentication request
			VerificationResult verification = getConsumerManager(request)
					.verify(receivingURL.toString(), response, discovered);

			// examine the verification result and extract the verified
			// identifier
			Identifier verified = verification.getVerifiedId();
			if (verified != null)
				logInfo(DEBUG_ASSOCIATION, "openid.verified_identifier="
						+ verified.getIdentifier());
			else
				logInfo(DEBUG_ASSOCIATION, "openid.verified_identifier=null");
			if (verified != null) {
				AuthSuccess authSuccess = (AuthSuccess) verification
						.getAuthResponse();

				if (authSuccess.hasExtension(AxMessage.OPENID_NS_AX)) {
					/*
					 * FetchResponse fetchResp = (FetchResponse) authSuccess
					 * .getExtension(AxMessage.OPENID_NS_AX);
					 * 
					 * List emails = fetchResp.getAttributeValues("email");
					 * String email = (String) emails.get(0);
					 */
				}

				return verified; // success
			}
		} catch (OpenIDException e) {
			// present error to the user
			e.printStackTrace();
		}

		return null;
	}
}