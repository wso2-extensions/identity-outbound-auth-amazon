/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.authenticator.amazon;

public class AmazonAuthenticatorConstants {
    public static final String AUTHENTICATOR_NAME = "AmazonAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Amazon";

    //Amazon authorize endpoint URL
    public static final String AMAZON_OAUTH_ENDPOINT = "https://www.amazon.com/ap/oa";
    //Amazon token  endpoint URL
    public static final String AMAZON_TOKEN_ENDPOINT = "https://api.amazon.com/auth/o2/token";
    //Amazon user info endpoint URL
    public static final String AMAZON_USERINFO_ENDPOINT = "https://api.amazon.com/user/profile";

    public static final String CLIENT_ID="Client Id";
    public static final String CLIENT_SECRET="Client Secret";
    public static final String CALLBACK_URL="Callback URL";
    public static final String USER_ID="user_id";
    public static final String AMAZON_SCOPE_PROFILE = "profile";
}