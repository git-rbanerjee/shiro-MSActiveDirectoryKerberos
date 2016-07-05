/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.realm.krb;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;


import java.io.File;
import java.io.FileNotFoundException;
import java.security.NoSuchAlgorithmException;
 
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;



/* 
 * This code is intended for doing authentication using Microsoft Windows Active Directory
 * via kerberos in Apache-Shiro . 
 *
 * @author rabin.banerjee91@gmail.com
 */
public class MSActiveKRBRealm extends AuthorizingRealm {

	private static final Logger LOG = LoggerFactory.getLogger(MSActiveKRBRealm.class);

	
	private String krbfile ;
		
		// Name of our login config file
	private String loginfile ;
		
		// Name of our login module
	private String module ;
 
		
	public void setKrbfile(String krbfile){
		this.krbfile = krbfile;
	}


	public void setLoginfile(String loginfile){
		this.loginfile = loginfile;
	}


	public void setModule(String module){
		this.module = module;
	}

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		Set<String> roles = new LinkedHashSet<String>();

		UserPrincipal user = principals.oneByType(UserPrincipal.class);
		if (user != null) {
			roles.add("roles1");
		}
		return new SimpleAuthorizationInfo(roles);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
		AuthenticationToken token) throws AuthenticationException {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		String user = upToken.getUsername().toString();
		String passwd = new String(upToken.getPassword());
		try{
		validate(user,passwd,krbfile,loginfile,module);

		final CallbackHandler handler = 
        			getUsernamePasswordHandler(user, passwd);
 
        	final LoginContext loginContext = new LoginContext(module, handler);
 
		// attempt to login
		loginContext.login();
	 
		// output some info
		LOG.warn("Subject=" + loginContext.getSubject());
	 
		// logout
		loginContext.logout();
	 
		LOG.warn("Connection test successful.");



		}catch(Exception e)
		{ 
			if (e.getMessage().contains("Client not found in Kerberos database"))
		    	{
			    LOG.warn("User not found");
		    	}else if (e.getMessage().contains("Pre-authentication information was invalid"))
		    	{
		    		LOG.warn("Probably incorrect password, check your credential");
		    	} else {
				LOG.error("Exception in login: ", e);
		    	}

			throw new AuthenticationException(e);
		}


		return new SimpleAuthenticationInfo(new UserPrincipal(user), passwd,
				getName());
	}

	@Override
	protected void onInit() {
		super.onInit();
		try {
			//getMSActiveKRBRealm();
			// set some system properties
				System.setProperty("java.security.krb5.conf", krbfile);
				System.setProperty("java.security.auth.login.config", loginfile);
				System.setProperty("sun.security.krb5.debug", "true");
		} catch (Exception e) {
			throw new ShiroException("Cannot obtain PAM subsystem.", e);
		}
	}

	
	protected MSActiveKRBRealm getMSActiveKRBRealm() throws Exception {
		return new MSActiveKRBRealm();
	}

	private String authenticate(String userName,String password) throws Exception{

		return userName;

	}


	private void validate(final String username, final String password, final String krbfile, 
		final String loginfile, final String moduleName) throws FileNotFoundException,
		 NoSuchAlgorithmException {
 
		// confirm username was provided
		if (null == username || username.isEmpty()) {
		  throw new IllegalArgumentException("Must provide a username");
		}
	 
		// confirm password was provided
		if (null == password || password.isEmpty()) {
		  throw new IllegalArgumentException("Must provide a password");
		}
	 
		// confirm krb5.conf file exists
		if (null == krbfile || krbfile.isEmpty()) {
		  throw new IllegalArgumentException("Must provide a krb5 file");
		} else {
		  final File file = new File(krbfile);
		  if (!file.exists()) {
			throw new FileNotFoundException(krbfile);
		  }
		}
	 
		// confirm loginfile
		if (null == loginfile || loginfile.isEmpty()) {
		  throw new IllegalArgumentException("Must provide a login file");
		} else {
		  final File file = new File(loginfile);
		  if (!file.exists()) {
			throw new FileNotFoundException(loginfile);
		  }
		}
	 
		// confirm that runtime loaded the login file
		final Configuration config = Configuration.getConfiguration();
	 
		// confirm that the module name exists in the file
		if (null == config.getAppConfigurationEntry(moduleName)) {
		  throw new IllegalArgumentException("The module name " 
				+ moduleName + " was not found in the login file");
		}	
	  }

	  	private CallbackHandler getUsernamePasswordHandler(
			final String username, final String password) {
	 
		final CallbackHandler handler = new CallbackHandler() {
		  public void handle(final Callback[] callback) {
			for (int i = 0; i < callback.length; i++) {
			  if (callback[i] instanceof NameCallback) {
				final NameCallback nameCallback = (NameCallback) callback[i];
				nameCallback.setName(username);
			  } else if (callback[i] instanceof PasswordCallback) {
				final PasswordCallback passCallback = (PasswordCallback) callback[i];
				passCallback.setPassword(password.toCharArray());
			  } else {
				System.err.println("Unsupported Callback: " 
					+ callback[i].getClass().getName());
			  }
			}
		  }
		};
	 
		return handler;
	  }



	private static class UserPrincipal {

		private final String user;
		UserPrincipal(String user) {
			this.user = user;
		}
		
		public String getUser() {
			return user;
		}
		
		@Override
		public String toString() {
			return getUser();
		}
	}
}
