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

import org.apache.http.impl.client.CloseableHttpClient;

/**
 * @author Lukas Skublik
 *
 */
public class GroupOrProjectProcessing extends ObjectProcessing {

	protected static final String ATTR_PATH = "path";

	protected static final String ATTR_DESCRIPTION = "description";
	protected static final String ATTR_VISIBILITY = "visibility";
	protected static final String ATTR_LFS_ENABLED = "lfs_enabled";
	 static final String ATTR_REQUEST_ACCESS_ENABLED = "request_access_enabled";

	public GroupOrProjectProcessing(GitlabRestConfiguration configuration, CloseableHttpClient httpclient) {
		super(configuration, httpclient);
	}
}
