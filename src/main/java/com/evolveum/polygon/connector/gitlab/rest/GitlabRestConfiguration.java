/**
 * Copyright (c) 2010-2017 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.evolveum.polygon.connector.gitlab.rest;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.StatefulConfiguration;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * @author Lukas Skublik
 *
 */
public class GitlabRestConfiguration extends AbstractConfiguration implements StatefulConfiguration{

	private String loginUrl;
	private String protocol;
	private GuardedString privateToken;
	private String[] groupsToManage;
	private String[] groupsToManageRegex;
	private Predicate<String> groupMatcher; // Cached predicate for performance
	private String objectAvatar;

	// HTTP Proxy settings
	private String httpProxyHost;
	private Integer httpProxyPort;
	private String httpProxyUser;
	private GuardedString httpProxyPassword;

	// HTTP Timeout settings (in milliseconds)
	private Integer httpConnectTimeout = 10000; // Default 10 seconds
	private Integer httpSocketTimeout = 10000; // Default 10 seconds
	private Integer httpConnectionRequestTimeout = 10000; // Default 10 seconds

	// Default access level for groups and projects
	private Integer defaultAccessLevel = 10; // Default to Guest

	// Control membership attribute format in executeQuery: true="id#accessLevel", false="id"
	private Boolean includeMembershipAccessLevel = false; // Default to "id" format

	private static final Log LOGGER = Log.getLog(GitlabRestConnector.class);

	@ConfigurationProperty(order = 1, displayMessageKey = "privateToken.display", helpMessageKey = "privateToken.help", required = true, confidential = true)
	public GuardedString getPrivateToken() {
		return privateToken;
	}
	/**
	 * Setter method for the "privateToken" attribute.
	 *
	 * @param privateToken
	 * the privateToken string value.
	 */
	public void setPrivateToken(GuardedString privateToken) {
		this.privateToken = privateToken;
	}

	@ConfigurationProperty(order = 3, displayMessageKey = "loginUrl.display", helpMessageKey = "loginUrl.help", required = true, confidential = false)
	public String getLoginURL() {
		return loginUrl;
	}

	public void setLoginURL(String loginURL) {
		this.loginUrl = loginURL;
	}

	// Add protocol configuration property to support https
	@ConfigurationProperty(order = 4, displayMessageKey = "protocol.display", helpMessageKey = "protocol.help", required = false, confidential = false)
	public String getProtocol() {
		return protocol;
	}

	// Add groupsToManage configuration property to limit number of groups and memberships in these groups that will be managed by connector. If null or empty then all groups.
	@ConfigurationProperty(order = 5, displayMessageKey = "groupsToManage.display", helpMessageKey = "groupsToManage.help", required = false, confidential = false)
	public String[] getGroupsToManage() {
		return groupsToManage;
	}

	// Add objectAvatar configuration property to support choose objectAvatar is selected or no by Groups and Project
	// Workaroud for issue https://gitlab.com/gitlab-org/gitlab/-/issues/25498
	//@ConfigurationProperty(order = 6, displayMessageKey = "objectAvatar.display", helpMessageKey = "objectAvatar.help", required = true, confidential = false)
	public String getObjectAvatar() {
		return objectAvatar;
	}

	public void setGroupsToManage(String[] groupsToManage) {
		this.groupsToManage = groupsToManage;
	}

	// Add groupsToManageRegex configuration property to support regex patterns for group filtering
	@ConfigurationProperty(order = 6, displayMessageKey = "groupsToManageRegex.display", helpMessageKey = "groupsToManageRegex.help", required = false, confidential = false)
	public String[] getGroupsToManageRegex() {
		return groupsToManageRegex;
	}

	public void setGroupsToManageRegex(String[] groupsToManageRegex) {
		this.groupsToManageRegex = groupsToManageRegex;
	}

	/**
	 * Returns the cached predicate for group matching.
	 * This predicate is populated during validation for performance.
	 *
	 * @return Predicate that matches group names, or null if no filtering is configured
	 */
	public Predicate<String> getGroupMatcher() {
		return groupMatcher;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public void setObjectAvatar(String objectAvatar) {
		this.objectAvatar = objectAvatar;
	}

	// HTTP Proxy getters and setters
	@ConfigurationProperty(order = 7, displayMessageKey = "httpProxyHost.display",
			helpMessageKey = "httpProxyHost.help",
			required = false, confidential = false)
	public String getHttpProxyHost() {
		return httpProxyHost;
	}

	public void setHttpProxyHost(String httpProxyHost) {
		this.httpProxyHost = httpProxyHost;
	}

	@ConfigurationProperty(order = 8, displayMessageKey = "httpProxyPort.display",
			helpMessageKey = "httpProxyPort.help",
			required = false, confidential = false)
	public Integer getHttpProxyPort() {
		return httpProxyPort;
	}

	public void setHttpProxyPort(Integer httpProxyPort) {
		this.httpProxyPort = httpProxyPort;
	}

	@ConfigurationProperty(order = 9, displayMessageKey = "httpProxyUser.display",
			helpMessageKey = "httpProxyUser.help",
			required = false, confidential = false)
	public String getHttpProxyUser() {
		return httpProxyUser;
	}

	public void setHttpProxyUser(String httpProxyUser) {
		this.httpProxyUser = httpProxyUser;
	}

	@ConfigurationProperty(order = 10, displayMessageKey = "httpProxyPassword.display",
			helpMessageKey = "httpProxyPassword.help",
			required = false, confidential = true)
	public GuardedString getHttpProxyPassword() {
		return httpProxyPassword;
	}

	public void setHttpProxyPassword(GuardedString httpProxyPassword) {
		this.httpProxyPassword = httpProxyPassword;
	}

	// HTTP Timeout getters and setters
	@ConfigurationProperty(order = 11, displayMessageKey = "httpConnectTimeout.display",
			helpMessageKey = "httpConnectTimeout.help",
			required = false, confidential = false)
	public Integer getHttpConnectTimeout() {
		return httpConnectTimeout;
	}

	public void setHttpConnectTimeout(Integer httpConnectTimeout) {
		this.httpConnectTimeout = httpConnectTimeout;
	}

	@ConfigurationProperty(order = 12, displayMessageKey = "httpSocketTimeout.display",
			helpMessageKey = "httpSocketTimeout.help",
			required = false, confidential = false)
	public Integer getHttpSocketTimeout() {
		return httpSocketTimeout;
	}

	public void setHttpSocketTimeout(Integer httpSocketTimeout) {
		this.httpSocketTimeout = httpSocketTimeout;
	}

	@ConfigurationProperty(order = 13, displayMessageKey = "httpConnectionRequestTimeout.display",
			helpMessageKey = "httpConnectionRequestTimeout.help",
			required = false, confidential = false)
	public Integer getHttpConnectionRequestTimeout() {
		return httpConnectionRequestTimeout;
	}

	public void setHttpConnectionRequestTimeout(Integer httpConnectionRequestTimeout) {
		this.httpConnectionRequestTimeout = httpConnectionRequestTimeout;
	}

	// Default access level getters and setters
	@ConfigurationProperty(order = 14, displayMessageKey = "defaultAccessLevel.display",
			helpMessageKey = "defaultAccessLevel.help",
			required = false, confidential = false)
	public Integer getDefaultAccessLevel() {
		return defaultAccessLevel;
	}

	public void setDefaultAccessLevel(Integer defaultAccessLevel) {
		this.defaultAccessLevel = defaultAccessLevel;
	}

	// Include membership access level getters and setters
	@ConfigurationProperty(order = 15, displayMessageKey = "includeMembershipAccessLevel.display",
			helpMessageKey = "includeMembershipAccessLevel.help",
			required = false, confidential = false)
	public Boolean getIncludeMembershipAccessLevel() {
		return includeMembershipAccessLevel;
	}

	public void setIncludeMembershipAccessLevel(Boolean includeMembershipAccessLevel) {
		this.includeMembershipAccessLevel = includeMembershipAccessLevel;
	}

	@Override
	public void validate() {
		LOGGER.info("Processing trough configuration validation procedure.");
		if (StringUtil.isBlank(loginUrl)) {
			throw new ConfigurationException("Login url cannot be empty.");
		}
		if (privateToken == null) {
			throw new ConfigurationException("Private Token cannot be empty.");
		}

		if (protocol == null || !(protocol.equals("http") || protocol.equals("https") || protocol.isEmpty())) {
			 throw new ConfigurationException("Protocol should be http or https.");
		}
		if (objectAvatar == null || !(objectAvatar.equals("true") || objectAvatar.equals("false") || objectAvatar.isEmpty())) {
			throw new ConfigurationException("objectAvatar should be true or false.");
		}

		// Build group matcher predicate combining literals and regex patterns
		List<Predicate<String>> predicates = new ArrayList<>();

		// Add literal matchers (case-insensitive)
		if (groupsToManage != null && groupsToManage.length > 0) {
			Set<String> literals = new HashSet<>();
			for (String group : groupsToManage) {
				if (group != null && !group.trim().isEmpty()) {
					literals.add(group.trim().toLowerCase());
				}
			}
			if (!literals.isEmpty()) {
				predicates.add(name -> literals.contains(name.toLowerCase()));
			}
		}

		// Add regex matchers (case-insensitive by default)
		if (groupsToManageRegex != null && groupsToManageRegex.length > 0) {
			for (String regex : groupsToManageRegex) {
				if (regex != null && !regex.trim().isEmpty()) {
					try {
						Pattern pattern = Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
						predicates.add(name -> pattern.matcher(name).matches());
					} catch (PatternSyntaxException e) {
						throw new ConfigurationException("Invalid regex pattern in groupsToManageRegex: " + regex + " - " + e.getMessage());
					}
				}
			}
		}

		// Combine all predicates with OR logic
		if (!predicates.isEmpty()) {
			groupMatcher = predicates.stream().reduce(Predicate::or).orElse(x -> false);
		} else {
			groupMatcher = null; // No filtering
		}

		// Validate proxy settings
		if (httpProxyPort != null && (httpProxyPort <= 0 || httpProxyPort > 65535)) {
			throw new ConfigurationException("HTTP Proxy Port must be between 1 and 65535.");
		}

		if (StringUtil.isNotBlank(httpProxyUser) && httpProxyPassword == null) {
			throw new ConfigurationException("HTTP Proxy Password is required when Proxy User is specified.");
		}

		// Validate timeout settings
		if (httpConnectTimeout != null && httpConnectTimeout <= 0) {
			throw new ConfigurationException("HTTP Connect Timeout must be greater than 0.");
		}

		if (httpSocketTimeout != null && httpSocketTimeout <= 0) {
			throw new ConfigurationException("HTTP Socket Timeout must be greater than 0.");
		}

		if (httpConnectionRequestTimeout != null && httpConnectionRequestTimeout <= 0) {
			throw new ConfigurationException("HTTP Connection Request Timeout must be greater than 0.");
		}

		// Validate default access level
		if (defaultAccessLevel != null && defaultAccessLevel <= 0) {
			throw new ConfigurationException("Default Access Level must be greater than 0.");
		}

		LOGGER.info("Configuration valid");
	}

	@Override
	public void release() {
		LOGGER.info("The release of configuration resources is being performed");
		this.loginUrl = null;                
		this.privateToken.dispose();
		this.protocol = null;
		this.groupsToManage = null;
		this.groupsToManageRegex = null;
		this.groupMatcher = null;
		this.objectAvatar = null;
		this.httpProxyHost = null;
		this.httpProxyPort = null;
		this.httpProxyUser = null;
		if (this.httpProxyPassword != null) {
			this.httpProxyPassword.dispose();
		}
		this.includeMembershipAccessLevel = null;
	}

	@Override
	public String toString() {
		return "GitlabRestConfiguration{" +
				", loginUrl='" + loginUrl + '\'' +
				'}';
	}
}