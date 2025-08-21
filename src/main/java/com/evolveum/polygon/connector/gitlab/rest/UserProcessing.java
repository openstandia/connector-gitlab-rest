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

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * @author Lukas Skublik
 *
 */
public class UserProcessing extends ObjectProcessing {

	private static final String STATUS_ACTIVE = "active";

	// mandatory attributes
	private static final String ATTR_MAIL = "email";

	// Either password, reset_password, or force_random_password must be specified.
	// If reset_password and force_random_password are both false, then password is
	// required.
	private static final String ATTR_PASSWORD = "password";
	private static final String ATTR_RESET_PASSWORD = "reset_password";
	private static final String ATTR_FORCE_RANDOM_PASSWORD = "force_random_password";

	// optional attributes
	private static final String ATTR_SKYPE = "skype";
	private static final String ATTR_LINKEDIN = "linkedin";
	private static final String ATTR_TWITTER = "twitter";
	private static final String ATTR_WEBSITE_URL = "website_url";
	private static final String ATTR_ORGANIZATION = "organization";
	private static final String ATTR_PROJECTS_LIMIT = "projects_limit";
	private static final String ATTR_BIO = "bio";
	private static final String ATTR_LOCATION = "location";
	private static final String ATTR_ADMIN = "admin";
	private static final String ATTR_IS_ADMIN = "is_admin";
	private static final String ATTR_CAN_CREATE_GROUP = "can_create_group";
	// Fix wrong attribute name for REST API. Old value "confirm" a new one
	// "skip_confirmation"
	private static final String ATTR_CONFIRM = "skip_confirmation";
	// Add new attribute "skip_reconfirmation" to fix "Update user email address via
	// API fails to change value"
	// https://gitlab.com/gitlab-org/gitlab-ce/issues/17797
	private static final String ATTR_RECONFIRM = "skip_reconfirmation";
	private static final String ATTR_EXTERNAL = "external";
	private static final String ATTR_STATE = "state";
	private static final String ATTR_LAST_SING_IN_AT = "last_sign_in_at";
	private static final String ATTR_LAST_ACTIVITY_ON = "last_activity_on";
	private static final String ATTR_CONFIRMED_AT = "confirmed_at";
	private static final String ATTR_COLOR_SCHEME_ID = "color_scheme_id";
	private static final String ATTR_CURR_SING_IN_AT = "current_sign_in_at";
	private static final String ATTR_IDENTITIES = "identities";
	private static final String ATTR_PROVIDER = "provider";
	private static final String ATTR_EXTERN_UID = "extern_uid";
	private static final String ATTR_CAN_CREATE_PROJ = "can_create_project";
	private static final String ATTR_TWO_FACTOR_ENABLED = "two_factor_enabled";
	private static final String ATTR_SSH_KEYS = "SSH_keys";
	protected static final String ATTR_GROUPS_AS_OWNER = "groups_as_owner";
	protected static final String ATTR_GROUPS_AS_MASTER = "groups_as_master";
	protected static final String ATTR_GROUPS_AS_DEVELOPER = "groups_as_developer";
	protected static final String ATTR_GROUPS_AS_REPORTER = "groups_as_reporter";
	protected static final String ATTR_GROUPS_AS_GUEST = "groups_as_guest";
	protected static final String ATTR_GROUPS = "groups";
	protected static final String ATTR_PROJECTS_AS_OWNER = "projects_as_owner";
	protected static final String ATTR_PROJECTS_AS_MASTER = "projects_as_master";
	protected static final String ATTR_PROJECTS_AS_DEVELOPER = "projects_as_developer";
	protected static final String ATTR_PROJECTS_AS_REPORTER = "projects_as_reporter";
	protected static final String ATTR_PROJECTS_AS_GUEST = "projects_as_guest";
	protected static final String ATTR_PROJECTS = "projects";
	// User memberships - Introduced in Gitlab 12.8
	protected static final String USERS_MEMBERSHIPS_URL = "/memberships";
	protected static final String TYPE_MEMBERSHIPS = "type";
	protected static final String TYPE_MEMBERSHIPS_GROUP = "Namespace";
	protected static final String TYPE_MEMBERSHIPS_PROJECT = "Project";
	protected static final String ATTR_USER_MEMBERSHIPS_SRC_ID = "source_id";
	protected static final String ATTR_USER_MEMBERSHIPS_ACCESS_LEVEL = "access_level";
	protected static final String ATTR_USER_MEMBERSHIPS_SRC_TYPE = "source_type";
	protected static final String ATTR_USER_MEMBERSHIPS_SRC_NAME = "source_name";
	// Constants for member management APIs
	private static final String ATTR_USER_ID = "user_id";
	private static final String ATTR_ACCESS_LEVEL = "access_level";

	protected static final Map<String, Integer> GROUP_ACCESS_LEVEL_MAP = Map.of(
			ATTR_GROUPS_AS_OWNER, 50,
			ATTR_GROUPS_AS_MASTER, 40,
			ATTR_GROUPS_AS_DEVELOPER, 30,
			ATTR_GROUPS_AS_REPORTER, 20,
			ATTR_GROUPS_AS_GUEST, 10
	);
	protected static final Map<String, Integer> PROJECT_ACCESS_LEVEL_MAP = Map.of(
			ATTR_PROJECTS_AS_OWNER, 50,
			ATTR_PROJECTS_AS_MASTER, 40,
			ATTR_PROJECTS_AS_DEVELOPER, 30,
			ATTR_PROJECTS_AS_REPORTER, 20,
			ATTR_PROJECTS_AS_GUEST, 10
	);
	protected static final Map<Integer, String> GROUP_ACCESS_LEVEL_MAP_REVERSED = GROUP_ACCESS_LEVEL_MAP.entrySet().stream()
			.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
	protected static final Map<Integer, String> PROJECT_ACCESS_LEVEL_MAP_REVERSED = PROJECT_ACCESS_LEVEL_MAP.entrySet().stream()
			.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));

	protected CloseableHttpClient httpclient;
	private GitlabRestConfiguration configuration;

	public UserProcessing(GitlabRestConfiguration configuration, CloseableHttpClient httpclient) {
		super(configuration, httpclient);
		this.configuration = configuration;
		this.httpclient = httpclient;
	}

	public void buildUserObjectClass(SchemaBuilder schemaBuilder) {
		ObjectClassInfoBuilder userObjClassBuilder = new ObjectClassInfoBuilder();

		userObjClassBuilder.setType(ObjectClass.ACCOUNT_NAME);

		// createable: TRUE && updateable: TRUE && readable: TRUE
		AttributeInfoBuilder attrMailBuilder = new AttributeInfoBuilder(ATTR_MAIL);
		attrMailBuilder.setRequired(true).setType(String.class).setCreateable(true).setUpdateable(true)
				.setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrMailBuilder.build());

		AttributeInfoBuilder attrNameBuilder = new AttributeInfoBuilder(ATTR_NAME);
		attrNameBuilder.setRequired(true).setType(String.class).setCreateable(true).setUpdateable(true)
				.setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrNameBuilder.build());

		AttributeInfoBuilder attrSkypeBuilder = new AttributeInfoBuilder(ATTR_SKYPE);
		attrSkypeBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrSkypeBuilder.build());

		AttributeInfoBuilder attrTwitterBuilder = new AttributeInfoBuilder(ATTR_TWITTER);
		attrTwitterBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrTwitterBuilder.build());

		AttributeInfoBuilder attrWebsiteUrlBuilder = new AttributeInfoBuilder(ATTR_WEBSITE_URL);
		attrWebsiteUrlBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrWebsiteUrlBuilder.build());

		AttributeInfoBuilder attrOrganizationBuilder = new AttributeInfoBuilder(ATTR_ORGANIZATION);
//		attrOrganizationBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		attrOrganizationBuilder.setType(String.class).setCreateable(false).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrOrganizationBuilder.build());

		AttributeInfoBuilder attrProjectLimitBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_LIMIT);
		attrProjectLimitBuilder.setType(Integer.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrProjectLimitBuilder.build());

		AttributeInfoBuilder attrBioBuilder = new AttributeInfoBuilder(ATTR_BIO);
		attrBioBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrBioBuilder.build());

		AttributeInfoBuilder attrLocationBuilder = new AttributeInfoBuilder(ATTR_LOCATION);
//		attrLocationBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		attrLocationBuilder.setType(String.class).setCreateable(false).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrLocationBuilder.build());

		AttributeInfoBuilder attrCanCreateGroupBuilder = new AttributeInfoBuilder(ATTR_CAN_CREATE_GROUP);
		attrCanCreateGroupBuilder.setType(Boolean.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrCanCreateGroupBuilder.build());

		AttributeInfoBuilder attrExternalBuilder = new AttributeInfoBuilder(ATTR_EXTERNAL);
		attrExternalBuilder.setType(Boolean.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrExternalBuilder.build());

		AttributeInfoBuilder attrLinkedinBuilder = new AttributeInfoBuilder(ATTR_LINKEDIN);
		attrLinkedinBuilder.setType(String.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrLinkedinBuilder.build());

		AttributeInfoBuilder attrIsAdminBuilder = new AttributeInfoBuilder(ATTR_IS_ADMIN);
		attrIsAdminBuilder.setType(Boolean.class).setCreateable(true).setUpdateable(true).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrIsAdminBuilder.build());

		// createable: TRUE && updateable: FALSE && readable: FALSE
		AttributeInfoBuilder attrConfirmBuilder = new AttributeInfoBuilder(ATTR_CONFIRM);
		attrConfirmBuilder.setType(Boolean.class).setCreateable(true).setUpdateable(false).setReadable(false)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrConfirmBuilder.build());

		// createable: FALSE && updateable: TRUE && readable: FALSE
		AttributeInfoBuilder attrReconfirmBuilder = new AttributeInfoBuilder(ATTR_RECONFIRM);
		attrReconfirmBuilder.setType(Boolean.class).setCreateable(false).setUpdateable(true).setReadable(false)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrReconfirmBuilder.build());

		// createable: FALSE && updateable: FALSE && readable: TRUE
		AttributeInfoBuilder attrAvatarUrlBuilder = new AttributeInfoBuilder(ATTR_AVATAR_URL);
		attrAvatarUrlBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrAvatarUrlBuilder.build());

		AttributeInfoBuilder attrCreateAtBuilder = new AttributeInfoBuilder(ATTR_CREATED_AT);
		attrCreateAtBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrCreateAtBuilder.build());

		AttributeInfoBuilder attrLastSingInAtBuilder = new AttributeInfoBuilder(ATTR_LAST_SING_IN_AT);
		attrLastSingInAtBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrLastSingInAtBuilder.build());

		AttributeInfoBuilder attrConfirmedAtBuilder = new AttributeInfoBuilder(ATTR_CONFIRMED_AT);
		attrConfirmedAtBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrConfirmedAtBuilder.build());

		AttributeInfoBuilder attrLastActivityOnBuilder = new AttributeInfoBuilder(ATTR_LAST_ACTIVITY_ON);
		attrLastActivityOnBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrLastActivityOnBuilder.build());

		AttributeInfoBuilder attrColorSchemeBuilder = new AttributeInfoBuilder(ATTR_COLOR_SCHEME_ID);
		attrColorSchemeBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrColorSchemeBuilder.build());

		AttributeInfoBuilder attrCurrSingInAtBuilder = new AttributeInfoBuilder(ATTR_CURR_SING_IN_AT);
		attrCurrSingInAtBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrCurrSingInAtBuilder.build());

		AttributeInfoBuilder attrCanCreateProjBuilder = new AttributeInfoBuilder(ATTR_CAN_CREATE_PROJ);
		attrCanCreateProjBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrCanCreateProjBuilder.build());

		AttributeInfoBuilder attrTwoFactorEnabledBuilder = new AttributeInfoBuilder(ATTR_TWO_FACTOR_ENABLED);
		attrTwoFactorEnabledBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrTwoFactorEnabledBuilder.build());

		AttributeInfoBuilder attrWebUrlBuilder = new AttributeInfoBuilder(ATTR_WEB_URL);
		attrWebUrlBuilder.setType(String.class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrWebUrlBuilder.build());

		AttributeInfoBuilder avatarBuilder = new AttributeInfoBuilder(ATTR_AVATAR);
//		avatarBuilder.setType(byte[].class).setCreateable(true).setUpdateable(true).setReadable(true);
		avatarBuilder.setType(byte[].class).setCreateable(false).setUpdateable(false).setReadable(true);
		userObjClassBuilder.addAttributeInfo(avatarBuilder.build());

		// multivalued: TRUE && createable: TRUE && updateable: TRUE && readable:TRUE
		AttributeInfoBuilder attrIdentitiesBuilder = new AttributeInfoBuilder(ATTR_IDENTITIES);
		attrIdentitiesBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true)
				.setReadable(true);
		userObjClassBuilder.addAttributeInfo(attrIdentitiesBuilder.build());

		AttributeInfoBuilder sshKeysBuilder = new AttributeInfoBuilder(ATTR_SSH_KEYS);
		sshKeysBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true)
				.setReadable(true);
		userObjClassBuilder.addAttributeInfo(sshKeysBuilder.build());

		// Group membership attributes - each attribute represents group memberships at a specific access level
		AttributeInfoBuilder attrGroupsAsOwnerBuilder = new AttributeInfoBuilder(ATTR_GROUPS_AS_OWNER);
		attrGroupsAsOwnerBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsAsOwnerBuilder.build());

		AttributeInfoBuilder attrGroupsAsMasterBuilder = new AttributeInfoBuilder(ATTR_GROUPS_AS_MASTER);
		attrGroupsAsMasterBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsAsMasterBuilder.build());

		AttributeInfoBuilder attrGroupsAsDeveloperBuilder = new AttributeInfoBuilder(ATTR_GROUPS_AS_DEVELOPER);
		attrGroupsAsDeveloperBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsAsDeveloperBuilder.build());

		AttributeInfoBuilder attrGroupsAsReporterBuilder = new AttributeInfoBuilder(ATTR_GROUPS_AS_REPORTER);
		attrGroupsAsReporterBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsAsReporterBuilder.build());

		AttributeInfoBuilder attrGroupsAsGuestBuilder = new AttributeInfoBuilder(ATTR_GROUPS_AS_GUEST);
		attrGroupsAsGuestBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsAsGuestBuilder.build());

		// Group membership attribute - represents all group memberships regardless of access level
		AttributeInfoBuilder attrGroupsBuilder = new AttributeInfoBuilder(ATTR_GROUPS);
		attrGroupsBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrGroupsBuilder.build());

		// Project membership attributes - each attribute represents project memberships at a specific access level
		AttributeInfoBuilder attrProjectsAsOwnerBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_AS_OWNER);
		attrProjectsAsOwnerBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsAsOwnerBuilder.build());

		AttributeInfoBuilder attrProjectsAsMasterBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_AS_MASTER);
		attrProjectsAsMasterBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsAsMasterBuilder.build());

		AttributeInfoBuilder attrProjectsAsDeveloperBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_AS_DEVELOPER);
		attrProjectsAsDeveloperBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsAsDeveloperBuilder.build());

		AttributeInfoBuilder attrProjectsAsReporterBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_AS_REPORTER);
		attrProjectsAsReporterBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsAsReporterBuilder.build());

		AttributeInfoBuilder attrProjectsAsGuestBuilder = new AttributeInfoBuilder(ATTR_PROJECTS_AS_GUEST);
		attrProjectsAsGuestBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsAsGuestBuilder.build());

		// Project membership attribute - represents all project memberships regardless of access level
		AttributeInfoBuilder attrProjectsBuilder = new AttributeInfoBuilder(ATTR_PROJECTS);
		attrProjectsBuilder.setType(String.class).setMultiValued(true).setCreateable(true).setUpdateable(true).setReadable(true)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrProjectsBuilder.build());

		// password related attributes
		userObjClassBuilder.addAttributeInfo(OperationalAttributeInfos.PASSWORD);

		AttributeInfoBuilder attrResetPasswordBuilder = new AttributeInfoBuilder(ATTR_RESET_PASSWORD);
		attrResetPasswordBuilder.setType(Boolean.class).setUpdateable(false).setReadable(false)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrResetPasswordBuilder.build());

		AttributeInfoBuilder attrForceRandomPasswordBuilder = new AttributeInfoBuilder(ATTR_FORCE_RANDOM_PASSWORD);
		attrForceRandomPasswordBuilder.setType(Boolean.class).setUpdateable(false).setReadable(false)
				.setReturnedByDefault(false);
		userObjClassBuilder.addAttributeInfo(attrForceRandomPasswordBuilder.build());

		// __ENABLE__
		userObjClassBuilder.addAttributeInfo(OperationalAttributeInfos.ENABLE);

		schemaBuilder.defineObjectClass(userObjClassBuilder.build());
	}

	public Uid createOrUpdateUser(Uid uid, Set<Attribute> attributes) {
		LOGGER.info("Start createOrUpdateUser, Uid: {0}, attributes: {1}", uid, attributes);

		// create or update
		Boolean create = (uid == null) ? true : false;

		JSONObject json = new JSONObject();

		// mandatory attributes
		putRequestedAttrIfExists(create, attributes, ATTR_MAIL, json);
		putRequestedAttrIfExists(create, attributes, "__NAME__", json, ATTR_USERNAME);
		putRequestedAttrIfExists(create, attributes, ATTR_NAME, json);

		// optional attributes
		putAttrIfExists(attributes, ATTR_SKYPE, String.class, json);
		putAttrIfExists(attributes, ATTR_LINKEDIN, String.class, json);
		putAttrIfExists(attributes, ATTR_TWITTER, String.class, json);
		putAttrIfExists(attributes, ATTR_WEBSITE_URL, String.class, json);
		putAttrIfExists(attributes, ATTR_ORGANIZATION, String.class, json);
		putAttrIfExists(attributes, ATTR_PROJECTS_LIMIT, Integer.class, json);
		putAttrIfExists(attributes, ATTR_BIO, String.class, json);
		putAttrIfExists(attributes, ATTR_LOCATION, String.class, json);
		putAttrIfExists(attributes, ATTR_IS_ADMIN, Boolean.class, json, ATTR_ADMIN);
		putAttrIfExists(attributes, ATTR_CAN_CREATE_GROUP, Boolean.class, json);
		putAttrIfExists(attributes, ATTR_EXTERNAL, Boolean.class, json);

		if (create) {
			putAttrIfExists(attributes, ATTR_CONFIRM, Boolean.class, json);
		}

		if (!create) {
			putAttrIfExists(attributes, ATTR_RECONFIRM, Boolean.class, json);
		}

//		for (Attribute attr : attributes) {
//			if (ATTR_AVATAR.equals(attr.getName())) {
//				List<Object> vals = attr.getValue();
//				if (vals != null && !vals.isEmpty()) {
//					byte[] value = (byte[]) vals.get(0);
//					String strValue = Base64.encodeBase64String(value);
//					json.put(ATTR_AVATAR, strValue);
//				}
//				
//			}
//		}

		LOGGER.info("User request (without password): {0}", json.toString());

		putRequestedPassword(create, attributes, json);

		Uid newUid = createPutOrPostRequest(uid, USERS, json, create);

		changeStateIfExists(attributes, newUid);

		if (create) {
			for (Attribute attr : attributes) {
				if (ATTR_SSH_KEYS.equals(attr.getName())) {
					List<Object> vals = attr.getValue();
					if (vals != null && !vals.isEmpty()) {
						Map<String, Integer> sshKeys = getSSHKeysAsMap(
								Integer.parseInt((String) (newUid.getValue().get(0))));
						for (Object value : vals) {
							addSSHKey(newUid, sshKeys, value);
						}
					}
				}
				if (ATTR_IDENTITIES.equals(attr.getName())) {
					List<Object> vals = attr.getValue();
					if (vals != null && !vals.isEmpty()) {
						for (Object value : vals) {
							addIdentities(newUid, value);
						}
					}
				}
				// Handle ATTR_GROUPS - supports format "id#accessLevel" or just "id"
				if (ATTR_GROUPS.equals(attr.getName())) {
					processMembershipAttributeForCreate(attr, newUid, true, null);
				}
				// Handle ATTR_PROJECTS - supports format "id#accessLevel" or just "id"
				if (ATTR_PROJECTS.equals(attr.getName())) {
					processMembershipAttributeForCreate(attr, newUid, false, null);
				}
				// Handle group memberships
				Integer groupAccessLevel = GROUP_ACCESS_LEVEL_MAP.get(attr.getName());
				if (groupAccessLevel != null) {
					processMembershipAttributeForCreate(attr, newUid, true, groupAccessLevel);
				}
				// Handle project memberships
				Integer projectAccessLevel = PROJECT_ACCESS_LEVEL_MAP.get(attr.getName());
				if (projectAccessLevel != null) {
					processMembershipAttributeForCreate(attr, newUid, false, projectAccessLevel);
				}
			}
		}

		return newUid;
	}

	private void changeStateIfExists(Set<Attribute> attributes, Uid uid) {

		LOGGER.info("ChangeStateIfExists attributes {0}, uid: {1}", attributes, uid);

		Boolean valueAttr = getAttr(attributes, OperationalAttributes.ENABLE_NAME, Boolean.class, null);
		if (valueAttr != null) {

			URIBuilder uriBuilder = getURIBuilder();
			URI uri;

			StringBuilder sbPath = new StringBuilder();
			sbPath.append(USERS).append("/").append(uid.getUidValue()).append("/");
			if (valueAttr) {
				sbPath.append("unblock");
			} else {
				sbPath.append("block");
			}
			uriBuilder.setPath(sbPath.toString());

			try {
				uri = uriBuilder.build();
			} catch (URISyntaxException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("It was not possible create URI from UriBuider:").append(uriBuilder).append("; ")
						.append(e.getLocalizedMessage());
				throw new ConnectorException(sb.toString(), e);
			}

			HttpEntityEnclosingRequestBase request;
			request = new HttpPost(uri);

			// execute request
			callRequest(request, false);
		}
	}

	private void modifyIdentities(Uid uid, Object value, Boolean addOrRemove) {

		if (value == null) {
			return;
		}

		JSONObject json = new JSONObject();
		String provider = ((String) value).split(":")[0];
		String exterUid = ((String) value).split(":")[1];
		if (addOrRemove) {
			json.put(ATTR_EXTERN_UID, exterUid);
		} else {
			json.put(ATTR_EXTERN_UID, JSONObject.NULL);
		}
		json.put(ATTR_PROVIDER, provider);

		createPutOrPostRequest(uid, USERS, json, false);

	}

	private void addIdentities(Uid uid, Object value) {
		modifyIdentities(uid, value, true);
	}

	private void removeIdentities(Uid uid, Object value) {
		modifyIdentities(uid, value, false);
	}

	private void modifySSHKey(Uid uid, Map<String, Integer> sshKeys, Object value, boolean addOrRemoveValue) {

		if (value == null) {
			return;
		}

		boolean matchSSHKey = false;
		Uid removeUid = null;
		for (String key : sshKeys.keySet()) {
			if (key.equals((String) value)) {
				matchSSHKey = true;
				removeUid = new Uid(String.valueOf(sshKeys.get(key)));
				break;
			}
		}
		if (addOrRemoveValue && !matchSSHKey) {
			JSONObject jsonSshKeys = new JSONObject();
			DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
			LocalDateTime now = LocalDateTime.now();
			StringBuilder title = new StringBuilder();
			title.append("Date of creation: ").append(dtf.format(now));
			jsonSshKeys.put("title", title.toString());

			jsonSshKeys.put("key", (String) value);
			LOGGER.info("String sshKey: {0}", (String) value);
			StringBuilder sb = new StringBuilder();
			sb.append(USERS).append("/").append(uid.getValue().get(0)).append(KEYS);

			createPutOrPostRequest(null, sb.toString(), jsonSshKeys, true);

		} else if (!addOrRemoveValue && matchSSHKey) {
			StringBuilder sb = new StringBuilder();
			sb.append(USERS).append("/").append(uid.getValue().get(0)).append(KEYS);
			executeDeleteOperation(removeUid, sb.toString());

		}
	}

	private void addSSHKey(Uid uid, Map<String, Integer> sshKeys, Object value) {
		modifySSHKey(uid, sshKeys, value, true);
	}

	private void removeSSHKey(Uid uid, Map<String, Integer> sshKeys, Object value) {
		modifySSHKey(uid, sshKeys, value, false);
	}

	private ConnectorObjectBuilder convertUserJSONObjectToConnectorObject(JSONObject user, Set<String> sshKeys,
			byte[] avatarPhoto, List<String> identities) {
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setObjectClass(ObjectClass.ACCOUNT);

		getUIDIfExists(user, UID, builder);

		getNAMEIfExists(user, ATTR_USERNAME, builder);

		getIfExists(user, ATTR_MAIL, String.class, builder);
		getIfExists(user, ATTR_NAME, String.class, builder);
		getIfExists(user, ATTR_WEB_URL, String.class, builder);
		getIfExists(user, ATTR_CREATED_AT, String.class, builder);
		getIfExists(user, ATTR_BIO, String.class, builder);
		getIfExists(user, ATTR_LOCATION, String.class, builder);
		getIfExists(user, ATTR_SKYPE, String.class, builder);
		getIfExists(user, ATTR_LINKEDIN, String.class, builder);
		getIfExists(user, ATTR_TWITTER, String.class, builder);
		getIfExists(user, ATTR_WEBSITE_URL, String.class, builder);
		getIfExists(user, ATTR_ORGANIZATION, String.class, builder);
		getIfExists(user, ATTR_LAST_SING_IN_AT, String.class, builder);
		getIfExists(user, ATTR_CONFIRMED_AT, String.class, builder);
		getIfExists(user, ATTR_LAST_ACTIVITY_ON, Integer.class, builder);
		getIfExists(user, ATTR_COLOR_SCHEME_ID, Integer.class, builder);
		getIfExists(user, ATTR_PROJECTS_LIMIT, Integer.class, builder);
		getIfExists(user, ATTR_CURR_SING_IN_AT, String.class, builder);
		getIfExists(user, ATTR_CAN_CREATE_GROUP, Boolean.class, builder);
		getIfExists(user, ATTR_CAN_CREATE_PROJ, Boolean.class, builder);
		getIfExists(user, ATTR_TWO_FACTOR_ENABLED, Boolean.class, builder);
		getIfExists(user, ATTR_EXTERNAL, Boolean.class, builder);
		getIfExists(user, ATTR_AVATAR_URL, String.class, builder);
		getIfExists(user, ATTR_IS_ADMIN, Boolean.class, builder);

		if (user.has(ATTR_STATE)) {
			boolean enable = STATUS_ACTIVE.equals(user.get(ATTR_STATE).toString());
			addAttr(builder, OperationalAttributes.ENABLE_NAME, enable);
		}

		addAttr(builder, ATTR_AVATAR, avatarPhoto);
		if (sshKeys != null) {
			builder.addAttribute(ATTR_SSH_KEYS, sshKeys);
		}
		if (identities != null) {
			builder.addAttribute(ATTR_IDENTITIES, identities.toArray());
		}

		return builder;
	}

	private Map<String, Integer> getSSHKeysAsMap(int userUid) {
		URIBuilder uriBuilder = getURIBuilder();
		StringBuilder path = new StringBuilder();
		path.append(USERS).append("/").append(userUid).append(KEYS);

		JSONArray objectsSSHKeys = new JSONArray();
		JSONArray partOfsSSHKeys = new JSONArray();
		int ii = 1;
		uriBuilder.setPath(path.toString());

		do {
			uriBuilder.clearParameters();
			uriBuilder.addParameter(PAGE, String.valueOf(ii));
			uriBuilder.addParameter(PER_PAGE, "100");
			HttpRequestBase requestSSHKey;
			try {
				requestSSHKey = new HttpGet(uriBuilder.build());
			} catch (URISyntaxException e) {
				StringBuilder sb = new StringBuilder();
				sb.append("It was not possible create URI from UriBuilder; ").append(e.getLocalizedMessage());
				throw new ConnectorException(sb.toString(), e);
			}
			partOfsSSHKeys = callRequestForJSONArray(requestSSHKey, true);
			Iterator<Object> iterator = partOfsSSHKeys.iterator();
			while (iterator.hasNext()) {
				Object sshKey = iterator.next();
				objectsSSHKeys.put(sshKey);
			}
			ii++;
		} while (partOfsSSHKeys.length() == 100);

		Map<String, Integer> sshKeys = new HashMap<String, Integer>();
		for (int i = 0; i < objectsSSHKeys.length(); i++) {
			JSONObject jsonObjectMember = objectsSSHKeys.getJSONObject(i);
			String sshKey = ((String) jsonObjectMember.get("key"));
			String unescapesshKey = StringEscapeUtils.unescapeXml(sshKey);
			sshKeys.put(unescapesshKey, ((Integer) jsonObjectMember.get(UID)));
		}
		return sshKeys;
	}

	public void executeQueryForUser(Filter query, ResultsHandler handler, OperationOptions options) {
		Set<String> attributesToGetSet = toAttributesToGetSet(options);
		boolean allowPartialAttributeValues = hasAllowPartialAttributeValuesOption(options);

		if (query instanceof EqualsFilter) {

			if (((EqualsFilter) query).getAttribute() instanceof Uid) {

				Uid uid = (Uid) ((EqualsFilter) query).getAttribute();
				if (uid.getUidValue() == null) {
					invalidAttributeValue("Uid", query);
				}
				StringBuilder sbPath = new StringBuilder();
				sbPath.append(USERS).append("/").append(uid.getUidValue());
				JSONObject user = (JSONObject) executeGetRequest(sbPath.toString(), null, options, false);
				processingObjectFromGET(user, handler, attributesToGetSet, allowPartialAttributeValues);

			} else if (((EqualsFilter) query).getAttribute() instanceof Name) {

				List<Object> allValues = ((EqualsFilter) query).getAttribute().getValue();
				if (allValues == null || allValues.get(0) == null) {
					invalidAttributeValue("Name", query);
				}
				Map<String, String> parameters = new HashMap<String, String>();
				parameters.put(ATTR_USERNAME, allValues.get(0).toString());
				JSONArray users = (JSONArray) executeGetRequest(USERS, parameters, options, true);
				processingObjectFromGET(users, handler, attributesToGetSet, allowPartialAttributeValues);

			} else if (((EqualsFilter) query).getAttribute().getName().equals(ATTR_IDENTITIES)) {

				List<Object> allValues = ((EqualsFilter) query).getAttribute().getValue();
				if (allValues == null || allValues.get(0) == null) {
					invalidAttributeValue("Name", query);
				}
				Map<String, String> parameters = new HashMap<String, String>();
				parameters.put(ATTR_PROVIDER, ((String) allValues.get(0)).split(":")[0].toString());
				parameters.put(ATTR_EXTERN_UID, ((String) allValues.get(0)).split(":")[1].toString());
				JSONArray users = (JSONArray) executeGetRequest(USERS, parameters, options, true);
				processingObjectFromGET(users, handler, attributesToGetSet, allowPartialAttributeValues);

			} else if (((EqualsFilter) query).getAttribute().getName().equals(ATTR_EXTERNAL)) {

				List<Object> allValues = ((EqualsFilter) query).getAttribute().getValue();
				if (allValues == null || allValues.get(0) == null) {
					invalidAttributeValue("Name", query);
				}
				Map<String, String> parameters = new HashMap<String, String>();
				parameters.put(ATTR_EXTERNAL, allValues.get(0).toString());
				JSONArray users = (JSONArray) executeGetRequest(USERS, parameters, options, true);
				processingObjectFromGET(users, handler, attributesToGetSet, allowPartialAttributeValues);
			} else {
				StringBuilder sb = new StringBuilder();
				sb.append("Illegal search with attribute ").append(((EqualsFilter) query).getAttribute().getName())
						.append(" for query: ").append(query);
				LOGGER.error(sb.toString());
				throw new InvalidAttributeValueException(sb.toString());
			}

		} else if (query instanceof ContainsFilter) {

			if (((ContainsFilter) query).getAttribute().getName().equals(Name.NAME)
					|| ((ContainsFilter) query).getAttribute().getName().equals(ATTR_MAIL)
					|| ((ContainsFilter) query).getAttribute().getName().equals(ATTR_NAME)) {

				List<Object> allValues = ((ContainsFilter) query).getAttribute().getValue();
				if (allValues == null || allValues.get(0) == null) {
					invalidAttributeValue("__NAME__", query);
				}
				Map<String, String> parameters = new HashMap<String, String>();
				parameters.put(SEARCH, allValues.get(0).toString());
				JSONArray users = (JSONArray) executeGetRequest(USERS, parameters, options, true);
				processingObjectFromGET(users, handler, attributesToGetSet, allowPartialAttributeValues);

			} else {
				StringBuilder sb = new StringBuilder();
				sb.append("Illegal search with attribute ").append(((ContainsFilter) query).getAttribute().getName())
						.append(" for query: ").append(query);
				LOGGER.error(sb.toString());
				throw new InvalidAttributeValueException(sb.toString());
			}
		} else if (query == null) {
			JSONArray users = (JSONArray) executeGetRequest(USERS, null, options, true);
			processingObjectFromGET(users, handler, attributesToGetSet, allowPartialAttributeValues);
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append("Unexpected filter ").append(query.getClass());
			LOGGER.error(sb.toString());
			throw new ConnectorIOException(sb.toString());
		}
	}

	private void processingObjectFromGET(JSONObject user, ResultsHandler handler, Set<String> attributesToGetSet, boolean allowPartialAttributeValues) {
		byte[] avaratPhoto = getAvatarPhoto(user, ATTR_AVATAR_URL, ATTR_AVATAR);
		int userUidValue = getUIDIfExists(user, UID);
		Set<String> SSHKeys = getSSHKeysAsMap(userUidValue).keySet();
		List<String> identities = getAttributeForIdentities(user);
		ConnectorObjectBuilder builder = convertUserJSONObjectToConnectorObject(user, SSHKeys, avaratPhoto, identities);

		boolean groupsRequested = isGroupsRequested(attributesToGetSet);
		boolean projectsRequested = isProjectsRequested(attributesToGetSet);
		boolean allGroupsRequested = attributesToGetSet.contains(ATTR_GROUPS);
		boolean allProjectsRequested = attributesToGetSet.contains(ATTR_PROJECTS);

		if (groupsRequested || projectsRequested || allGroupsRequested || allProjectsRequested) {
			if (allowPartialAttributeValues) {
				// Skip fetching groups and projects
				// Add incomplete attributes for ATTR_GROUPS_AS_* and ATTR_PROJECTS_AS_* if requested
				for (String name : GROUP_ACCESS_LEVEL_MAP.keySet()) {
					if (attributesToGetSet.contains(name)) {
						addIncompleteAttribute(builder, name);
					}
				}
				// Add incomplete attributes for ATTR_GROUPS and ATTR_PROJECTS if requested
				if (allGroupsRequested) {
					addIncompleteAttribute(builder, ATTR_GROUPS);
				}
				if (allProjectsRequested) {
					addIncompleteAttribute(builder, ATTR_PROJECTS);
				}
			} else {
				// Fetch groups and projects
				final String type;
				if ((groupsRequested || allGroupsRequested) && (projectsRequested || allProjectsRequested)) {
					type = null;
				} else if (groupsRequested || allGroupsRequested) {
					type = TYPE_MEMBERSHIPS_GROUP;
				} else {
					type = TYPE_MEMBERSHIPS_PROJECT;
				}

				// Collect all groups and projects
				Set<String> allGroups = new HashSet<>();
				Set<String> allProjects = new HashSet<>();

				Map<String, List<String>> groups = getUserAccessAsStream(USERS + "/" + userUidValue + "/" + USERS_MEMBERSHIPS_URL, type)
						.filter(jsonObject -> GROUP_ACCESS_LEVEL_MAP_REVERSED.containsKey(jsonObject.getInt(ATTR_USER_MEMBERSHIPS_ACCESS_LEVEL))) // Filter by supported accessLevel
						.collect(Collectors.groupingBy(
								// Create map key as attribute name for the group or project
								jsonObject -> {
									Integer accessLevel = jsonObject.getInt(ATTR_USER_MEMBERSHIPS_ACCESS_LEVEL);
									String srcType = jsonObject.getString(ATTR_USER_MEMBERSHIPS_SRC_TYPE);
									String srcId = String.valueOf(jsonObject.getInt(ATTR_USER_MEMBERSHIPS_SRC_ID));

									// Collect all groups and projects for the consolidated attributes
									if (srcType.equals(TYPE_MEMBERSHIPS_GROUP)) {
										allGroups.add(formatMembershipValue(srcId, accessLevel));
										return GROUP_ACCESS_LEVEL_MAP_REVERSED.get(accessLevel);
									} else if (srcType.equals(TYPE_MEMBERSHIPS_PROJECT)) {
										allProjects.add(formatMembershipValue(srcId, accessLevel));
										return PROJECT_ACCESS_LEVEL_MAP_REVERSED.get(accessLevel);
									}
									return "";
								},
								Collectors.mapping(
										jsonObject -> String.valueOf(jsonObject.getInt(ATTR_USER_MEMBERSHIPS_SRC_ID)),
										Collectors.toList()
								)
						));

				// Add access-level specific attributes
				for (Map.Entry<String, List<String>> entrySet : groups.entrySet()) {
					if (entrySet.getKey().isEmpty()) {
						continue;
					}
					AttributeBuilder attrBuilder = new AttributeBuilder();
					attrBuilder.setName(entrySet.getKey());
					attrBuilder.addValue(entrySet.getValue());
					builder.addAttribute(attrBuilder.build());
				}

				// Add consolidated ATTR_GROUPS attribute if requested
				if (allGroupsRequested && !allGroups.isEmpty()) {
					AttributeBuilder attrBuilder = new AttributeBuilder();
					attrBuilder.setName(ATTR_GROUPS);
					attrBuilder.addValue(new ArrayList<>(allGroups));
					builder.addAttribute(attrBuilder.build());
				}

				// Add consolidated ATTR_PROJECTS attribute if requested
				if (allProjectsRequested && !allProjects.isEmpty()) {
					AttributeBuilder attrBuilder = new AttributeBuilder();
					attrBuilder.setName(ATTR_PROJECTS);
					attrBuilder.addValue(new ArrayList<>(allProjects));
					builder.addAttribute(attrBuilder.build());
				}
			}
		}

		ConnectorObject connectorObject = builder.build();
		LOGGER.info("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}", user.get(UID),
				connectorObject.toString());
		handler.handle(connectorObject);
	}

	private Set<String> toAttributesToGetSet(OperationOptions options) {
		String[] attributesToGet = options.getAttributesToGet();
		if (attributesToGet == null) {
			return Collections.emptySet();
		}
		return new HashSet<>(Arrays.asList(attributesToGet));
	}

	private boolean hasAllowPartialAttributeValuesOption(OperationOptions options) {
		return Boolean.TRUE.equals(options.getAllowPartialAttributeValues());
	}

	private boolean isGroupsRequested(Set<String> attributesToGetSet) {
		return !Collections.disjoint(GROUP_ACCESS_LEVEL_MAP.keySet(), attributesToGetSet);
	}

	private boolean isProjectsRequested(Set<String> attributesToGetSet) {
		return !Collections.disjoint(PROJECT_ACCESS_LEVEL_MAP.keySet(), attributesToGetSet);
	}

	private void processingObjectFromGET(JSONArray users, ResultsHandler handler, Set<String> attributesToGetSet, boolean allowPartialAttributeValuess) {
		JSONObject user;
		for (int i = 0; i < users.length(); i++) {
			user = users.getJSONObject(i);
			processingObjectFromGET(user, handler, attributesToGetSet, allowPartialAttributeValuess);
		}
	}

	public void updateDeltaMultiValues(Uid uid, Set<AttributeDelta> attributesDelta, OperationOptions options) {
		for (AttributeDelta attrDelta : attributesDelta) {

			if (ATTR_IDENTITIES.equals(attrDelta.getName())) {

				List<Object> addValues = attrDelta.getValuesToAdd();
				List<Object> removeValues = attrDelta.getValuesToRemove();
				if (removeValues != null && !removeValues.isEmpty()) {
					for (Object removeValue : removeValues) {

						removeIdentities(uid, removeValue);
					}
				}
				if (addValues != null && !addValues.isEmpty()) {

					for (Object addValue : addValues) {
						addIdentities(uid, addValue);
					}
				}
			}

			if (ATTR_SSH_KEYS.equals(attrDelta.getName())) {

				List<Object> addValues = attrDelta.getValuesToAdd();
				List<Object> removeValues = attrDelta.getValuesToRemove();
				if (removeValues != null && !removeValues.isEmpty()) {
					Map<String, Integer> sshKeys = getSSHKeysAsMap(Integer.parseInt((String) (uid.getValue().get(0))));
					for (Object removeValue : removeValues) {

						removeSSHKey(uid, sshKeys, removeValue);
					}
				}
				if (addValues != null && !addValues.isEmpty()) {
					Map<String, Integer> sshKeys = getSSHKeysAsMap(Integer.parseInt((String) (uid.getValue().get(0))));
					for (Object addValue : addValues) {

						addSSHKey(uid, sshKeys, addValue);
					}
				}
			}

			// Handle ATTR_GROUPS delta changes - supports format "id#accessLevel" or just "id"
			if (ATTR_GROUPS.equals(attrDelta.getName())) {
				processMembershipAttributeForDelta(attrDelta, uid, true);
			}

			// Handle ATTR_PROJECTS delta changes - supports format "id#accessLevel" or just "id"
			if (ATTR_PROJECTS.equals(attrDelta.getName())) {
				processMembershipAttributeForDelta(attrDelta, uid, false);
			}
		}

		// Process group membership changes collectively
		processGroupMembershipChanges(uid, attributesDelta);

		// Process project membership changes collectively
		processProjectMembershipChanges(uid, attributesDelta);
	}

	private List<String> getAttributeForIdentities(JSONObject object) {

		List<String> identities = new ArrayList<>();

		Object valueObject = object.get(ATTR_IDENTITIES);
		if (valueObject != null && !JSONObject.NULL.equals(valueObject)) {
			if (valueObject instanceof JSONArray) {
				JSONArray objectArray = (JSONArray) valueObject;
				for (int i = 0; i < objectArray.length(); i++) {
					if (objectArray.get(i) instanceof JSONObject) {
						JSONObject jsonObject = objectArray.getJSONObject(i);
						String provider = String.valueOf(jsonObject.get(ATTR_PROVIDER));
						String externUid = String.valueOf(jsonObject.get(ATTR_EXTERN_UID));
						if (!externUid.equals("null")) {
							StringBuilder sb = new StringBuilder();
							sb.append(provider).append(":").append(externUid);
							String unescapeIdentity = StringEscapeUtils.unescapeXml(sb.toString());
							identities.add(unescapeIdentity);
						}
					}
				}

				if (!identities.isEmpty()) {
					return identities;
				}
			}
		}
		return null;
	}

	public Stream<JSONObject> getUserAccessAsStream(String sbPath, String type) {
		LOGGER.info("getUserAccess Start");
		// Get groups or project to manage is informed by user on connector configuration
		Map<String, String> groupsToManage = getGroupsForFilter(this.configuration.getGroupsToManage());
		Map<String, String> parameters = new HashMap<String, String>();

		parameters.put(PER_PAGE, "100");
		if (type != null) {
			parameters.put(TYPE_MEMBERSHIPS, type);
		}

		// Get all groups or projects for user
		JSONArray partOfGroupsOrProjects = (JSONArray) executeGetRequest(sbPath, parameters, null, true);

		Stream<JSONObject> jsonObjectStream = IntStream.range(0, partOfGroupsOrProjects.length())
				.mapToObj(partOfGroupsOrProjects::getJSONObject)
				.filter(jsonObject -> {
					if (groupsToManage == null) {
						return true;
					}
					return groupsToManage.containsKey(jsonObject.getString(ATTR_USER_MEMBERSHIPS_SRC_NAME).toLowerCase());
				});

		LOGGER.info("getUserAccess End");

		return jsonObjectStream;
	}

	private Map<String, String> getGroupsForFilter(String groupsToManage) {
		LOGGER.info("getGroupsForFilter Start");
		Map<String, String> groupArr = new HashMap<String, String>();
		if (groupsToManage == null || groupsToManage.isEmpty()) {
			return null;
		}
		String[] values = groupsToManage.toLowerCase().split(",");
		for (String value : values) {
			groupArr.put(value, value);
		}
		LOGGER.info("getGroupsForFilter End");
		return groupArr;
	}

	private void updateMemberAccessLevel(String userId, String groupOrProjectId, int accessLevel, boolean isGroup) {
		LOGGER.info("Updating member access level - User: {0}, ID: {1}, AccessLevel: {2}, IsGroup: {3}",
				userId, groupOrProjectId, accessLevel, isGroup);

		String path = isGroup ? GROUPS : PROJECTS;
		StringBuilder sbPath = new StringBuilder();
		sbPath.append(path).append("/").append(groupOrProjectId).append(MEMBERS);

		JSONObject json = new JSONObject();
		json.put(ATTR_ACCESS_LEVEL, accessLevel);

		// Use PUT request to update existing member
		createPutOrPostRequest(new Uid(userId), sbPath.toString(), json, false);
	}

	private void addMemberToGroupOrProject(String userId, String groupOrProjectId, int accessLevel, boolean isGroup) {
		LOGGER.info("Adding member - User: {0}, ID: {1}, AccessLevel: {2}, IsGroup: {3}",
				userId, groupOrProjectId, accessLevel, isGroup);

		String path = isGroup ? GROUPS : PROJECTS;
		StringBuilder sbPath = new StringBuilder();
		sbPath.append(path).append("/").append(groupOrProjectId).append(MEMBERS);

		JSONObject json = new JSONObject();
		json.put(ATTR_USER_ID, userId);
		json.put(ATTR_ACCESS_LEVEL, accessLevel);

		try {
			// Use POST request to add new member
			createPutOrPostRequest(null, sbPath.toString(), json, true);
		} catch (AlreadyExistsException e) {
			// GitLab returns 409 Conflict with "Member already exists" when member exists with different access level
			// Retry with update method if member already exists
			LOGGER.info("Member already exists with different access level, updating access level instead");
			updateMemberAccessLevel(userId, groupOrProjectId, accessLevel, isGroup);
		}
	}

	private void removeMemberFromGroupOrProject(String userId, String groupOrProjectId, boolean isGroup) {
		LOGGER.info("Removing member - User: {0}, ID: {1}, IsGroup: {2}",
				userId, groupOrProjectId, isGroup);

		String path = isGroup ? GROUPS : PROJECTS;
		StringBuilder sbPath = new StringBuilder();
		sbPath.append(path).append("/").append(groupOrProjectId).append(MEMBERS);

		executeDeleteOperation(new Uid(userId), sbPath.toString());
	}

	private void processGroupMembershipChanges(Uid uid, Set<AttributeDelta> attributesDelta) {
		collectAndProcessMembershipChanges(uid, attributesDelta, GROUP_ACCESS_LEVEL_MAP, true);
	}

	private void processProjectMembershipChanges(Uid uid, Set<AttributeDelta> attributesDelta) {
		collectAndProcessMembershipChanges(uid, attributesDelta, PROJECT_ACCESS_LEVEL_MAP, false);
	}

	private void collectAndProcessMembershipChanges(Uid uid, Set<AttributeDelta> attributesDelta,
													Map<String, Integer> accessLevelMap, boolean isGroup) {
		// Collect all additions and removals across all access levels
		Map<String, Integer> toAdd = new HashMap<>(); // entityId -> accessLevel
		Set<String> toRemove = new HashSet<>();

		for (AttributeDelta attrDelta : attributesDelta) {
			// Check if this attribute is in the access level map
			Integer accessLevel = accessLevelMap.get(attrDelta.getName());

			if (accessLevel != null) {
				// Collect removals
				List<Object> removeValues = attrDelta.getValuesToRemove();
				if (removeValues != null) {
					for (Object value : removeValues) {
						if (value != null) {
							toRemove.add((String) value);
						}
					}
				}

				// Collect additions
				List<Object> addValues = attrDelta.getValuesToAdd();
				if (addValues != null) {
					for (Object value : addValues) {
						if (value != null) {
							toAdd.put((String) value, accessLevel);
						}
					}
				}
			}
		}

		// Process the collected changes
		if (!toAdd.isEmpty() || !toRemove.isEmpty()) {
			processMembershipChanges(uid, toAdd, toRemove, isGroup);
		}
	}

	private void processMembershipChanges(Uid uid, Map<String, Integer> toAdd, Set<String> toRemove, boolean isGroup) {
		// Find entities that are in both add and remove (access level change)
		Set<String> toUpdate = new HashSet<>();
		for (String entityId : toAdd.keySet()) {
			if (toRemove.contains(entityId)) {
				toUpdate.add(entityId);
			}
		}

		// Update access levels for entities that are being modified
		for (String entityId : toUpdate) {
			Integer newAccessLevel = toAdd.get(entityId);
			updateMemberAccessLevel(uid.getUidValue(), entityId, newAccessLevel, isGroup);
		}

		// Remove entities from both sets if they were updated
		toUpdate.forEach(entityId -> {
			toAdd.remove(entityId);
			toRemove.remove(entityId);
		});

		// Process remaining removals (pure removes, not access level changes)
		for (String entityId : toRemove) {
			removeMemberFromGroupOrProject(uid.getUidValue(), entityId, isGroup);
		}

		// Process remaining additions (pure adds, not access level changes)
		for (Map.Entry<String, Integer> entry : toAdd.entrySet()) {
			addMemberToGroupOrProject(uid.getUidValue(), entry.getKey(), entry.getValue(), isGroup);
		}
	}

	private void putRequestedPassword(Boolean create, Set<Attribute> attributes, JSONObject json) {

		LOGGER.info("putRequestedPassword attributes: {0}, json: {1}", attributes.toString(), json.toString());

		final StringBuilder sbPass = new StringBuilder();

		GuardedString pass = getAttr(attributes, OperationalAttributes.PASSWORD_NAME, GuardedString.class, null);

		if (pass != null) {
			pass.access(new GuardedString.Accessor() {
				@Override
				public void access(char[] chars) {
					sbPass.append(new String(chars));
				}
			});

			json.put(ATTR_PASSWORD, sbPass.toString());

		} else if (create) {
			boolean resetPassword = getAttr(attributes, ATTR_RESET_PASSWORD, Boolean.class, false);
			if (resetPassword) {
				json.put(ATTR_RESET_PASSWORD, true);
			}
			boolean forceRandomPassword = getAttr(attributes, ATTR_FORCE_RANDOM_PASSWORD, Boolean.class, false);
			if (forceRandomPassword) {
				json.put(ATTR_FORCE_RANDOM_PASSWORD, true);
			}

			if (!resetPassword && !forceRandomPassword) {
				StringBuilder sb = new StringBuilder();
				sb.append("Missing value of required attribute:").append(OperationalAttributes.PASSWORD_NAME)
						.append("; for creating user");
				LOGGER.error(sb.toString());
				throw new InvalidAttributeValueException(sb.toString());
			}
		}
	}

	/**
	 * Helper method to process membership attributes during create operations.
	 *
	 * @param attr The attribute to process
	 * @param uid The user ID
	 * @param isGroup Whether this is for groups (true) or projects (false)
	 * @param fixedAccessLevel Fixed access level to use for all values, or null to resolve per value
	 */
	private void processMembershipAttributeForCreate(Attribute attr, Uid uid, boolean isGroup, Integer fixedAccessLevel) {
		List<Object> vals = attr.getValue();
		if (vals != null && !vals.isEmpty()) {
			for (Object value : vals) {
				if (value != null) {
					String strValue = (String) value;
					String entityId = extractEntityId(strValue);
					int accessLevel = (fixedAccessLevel != null) ? fixedAccessLevel : resolveAccessLevel(strValue, attr.getName());
					addMemberToGroupOrProject(uid.getUidValue(), entityId, accessLevel, isGroup);
				}
			}
		}
	}

	/**
	 * Helper method to process membership attributes that support "id#accessLevel" format during delta operations.
	 * Handles access level changes intelligently by detecting when the same entity ID is being removed and added.
	 */
	private void processMembershipAttributeForDelta(AttributeDelta attrDelta, Uid uid, boolean isGroup) {
		List<Object> addValues = attrDelta.getValuesToAdd();
		List<Object> removeValues = attrDelta.getValuesToRemove();

		// Collect entity IDs being removed and added
		Map<String, Integer> toAdd = new HashMap<>(); // entityId -> accessLevel
		Set<String> toRemove = new HashSet<>();

		// Process removals
		if (removeValues != null && !removeValues.isEmpty()) {
			for (Object removeValue : removeValues) {
				if (removeValue != null) {
					String entityId = extractEntityId((String) removeValue);
					toRemove.add(entityId);
				}
			}
		}

		// Process additions
		if (addValues != null && !addValues.isEmpty()) {
			for (Object addValue : addValues) {
				if (addValue != null) {
					String strValue = (String) addValue;
					int accessLevel = resolveAccessLevel(strValue, attrDelta.getName());
					String entityId = extractEntityId(strValue);
					toAdd.put(entityId, accessLevel);
				}
			}
		}

		// Process the collected changes using existing logic
		if (!toAdd.isEmpty() || !toRemove.isEmpty()) {
			processMembershipChanges(uid, toAdd, toRemove, isGroup);
		}
	}

	/**
	 * Resolves the access level for a given value, supporting "id#accessLevel" format.
	 *
	 * @param value The value which may contain "id#accessLevel" or just "id"
	 * @param attributeName The attribute name for logging purposes
	 * @return The resolved access level
	 */
	private int resolveAccessLevel(String value, String attributeName) {
		int accessLevel = configuration.getDefaultAccessLevel();

		if (value.contains("#")) {
			String[] parts = value.split("#", 2);
			try {
				accessLevel = Integer.parseInt(parts[1]);
			} catch (NumberFormatException e) {
				LOGGER.warn("Invalid access level format in {0}: {1}, using configured default level {2}",
						attributeName, value, configuration.getDefaultAccessLevel());
			}
		}

		return accessLevel;
	}

	/**
	 * Extracts the entity ID from a value, handling "id#accessLevel" format.
	 *
	 * @param value The value which may contain "id#accessLevel" or just "id"
	 * @return The entity ID part
	 */
	private String extractEntityId(String value) {
		return value.contains("#") ? value.split("#", 2)[0] : value;
	}

	private void addIncompleteAttribute(ConnectorObjectBuilder builder, String attributeName) {
		AttributeBuilder attrBuilder = new AttributeBuilder();
		attrBuilder.setName(attributeName).setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
		attrBuilder.addValue(Collections.EMPTY_LIST);
		builder.addAttribute(attrBuilder.build());
	}

	private String formatMembershipValue(String srcId, Integer accessLevel) {
		return configuration.getIncludeMembershipAccessLevel() ?
			srcId + "#" + accessLevel : srcId;
	}
}