/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.amazon;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.Assert;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.MockitoAnnotations.initMocks;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, AmazonAuthenticator.class, AuthenticatedUser.class, OAuthClientRequest.class})
public class AmazonAuthenticatorTest {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context;

    @Mock
    private AmazonAuthenticator mockAmazonAuthenticator;

    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Mock
    private OAuthAuthzResponse mockOAuthAuthzResponse;

    @Mock
    private AuthenticatedUser authenticatedUser;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;

    private AmazonAuthenticator amazonAuthenticator;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");
        return new Object[][] {{authenticatorProperties}};
    }

    @BeforeMethod
    public void setUp() {
        amazonAuthenticator = new AmazonAuthenticator();
        initMocks(this);
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) throws Exception {
        String authorizationServerEndpoint = amazonAuthenticator
                .getAuthorizationServerEndpoint(authenticatorProperties);
        Assert.assertEquals(AmazonAuthenticatorConstants.AMAZON_OAUTH_ENDPOINT, authorizationServerEndpoint);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndpoint = amazonAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(AmazonAuthenticatorConstants.AMAZON_TOKEN_ENDPOINT, tokenEndpoint);
    }
    @Test(description = "Test case for getUserInfoEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetUserInfoEndpoint(Map<String, String> authenticatorProperties) {
        String userInfoEndpoint = amazonAuthenticator.getUserInfoEndpoint(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(AmazonAuthenticatorConstants.AMAZON_USERINFO_ENDPOINT, userInfoEndpoint);
    }

    @Test(description = "Test case for requiredIdToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIdToken(Map<String, String> authenticatorProperties) {
        boolean isRequired = amazonAuthenticator.requiredIDToken(authenticatorProperties);
        Assert.assertFalse(isRequired);
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {
        String friendlyName = amazonAuthenticator.getFriendlyName();
        Assert.assertEquals(AmazonAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME, friendlyName);
    }

    @Test(description = "Test case for getName method")
    public void testGetName() {
        String name = amazonAuthenticator.getName();
        Assert.assertEquals(AmazonAuthenticatorConstants.AUTHENTICATOR_NAME, name);
    }

    @Test(description = "Test case for getScope method", dataProvider = "authenticatorProperties")
    public void testGetScope(Map<String, String> authenticatorProperties) {
        String scope = amazonAuthenticator.getScope("testscope", authenticatorProperties);
        Assert.assertEquals(AmazonAuthenticatorConstants.AMAZON_SCOPE_PROFILE, scope);
    }
    @Test(description = "Test case for processAuthenticationResponse method",
            dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        AmazonAuthenticator spyAuthenticator = PowerMockito.spy(new AmazonAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        PowerMockito.doReturn(oAuthClientResponse)
                .when(spyAuthenticator, "getOauthResponse", Mockito.any(OAuthClient.class),
                        Mockito.any(OAuthClientRequest.class));
        Mockito.when(oAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("test-token");
        PowerMockito.mockStatic(AuthenticatedUser.class);
        Mockito.when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(Mockito.anyString()))
                .thenReturn(authenticatedUser);
        HashMap<ClaimMapping, String> claimMappings = new HashMap<>();
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri("http://wso2.org/claims/sub");
        claimMapping.setLocalClaim(claim);
        claimMappings.put(new ClaimMapping(),"http://wso2.org/amazon/claims/user_id");
        claimMappings.put(claimMapping, "testuser");
        Mockito.when(spyAuthenticator.getSubjectAttributes(oAuthClientResponse, authenticatorProperties))
                .thenReturn(claimMappings);
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        Assert.assertNotNull(context.getSubject());
    }


    @Test(description = "Test case for processAuthenticationResponse method for access token null scenario",
            dataProvider = "authenticatorProperties", expectedExceptions = { AuthenticationFailedException.class })
    public void testProcessAuthenticationResponseForAccessTokenNull(Map<String, String> authenticatorProperties) throws Exception {
        AmazonAuthenticator spyAuthenticator = PowerMockito.spy(new AmazonAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        PowerMockito.doReturn(oAuthClientResponse).when(spyAuthenticator, "getOauthResponse", Mockito.any(OAuthClient.class),
                Mockito.any(OAuthClientRequest.class));
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for processAuthenticationResponse method for empty claims",
            dataProvider = "authenticatorProperties", expectedExceptions = { AuthenticationFailedException.class })
    public void testProcessAuthenticationResponseForEmptyClaims(Map<String, String> authenticatorProperties) throws Exception {
        AmazonAuthenticator spyAuthenticator = PowerMockito.spy(new AmazonAuthenticator());
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class)))
                .thenReturn(mockOAuthAuthzResponse);
        PowerMockito.doReturn(oAuthClientResponse).when(spyAuthenticator, "getOauthResponse", Mockito.any(OAuthClient.class),
                Mockito.any(OAuthClientRequest.class));
        Mockito.when(oAuthClientResponse.getParam(OIDCAuthenticatorConstants.ACCESS_TOKEN)).thenReturn("test-token");
        Mockito.when(spyAuthenticator.getSubjectAttributes(oAuthClientResponse, authenticatorProperties))
                .thenReturn(new HashMap<ClaimMapping, String>());
        context.setAuthenticatorProperties(authenticatorProperties);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for processAuthenticationResponse failed", dataProvider = "authenticatorProperties", expectedExceptions = {
            AuthenticationFailedException.class })
    public void testProcessAuthenticationResponseForOauthProblemException(Map<String, String> authenticatorProperties)
            throws AuthenticationFailedException {
        context.setAuthenticatorProperties(authenticatorProperties);
        amazonAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }

    @Test(description = "Test case for getOauthResponse method")
    public void testGetOauthResponse() throws Exception {
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        OAuthClientResponse oAuthClientResponse = Whitebox
                .invokeMethod(amazonAuthenticator, "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(oAuthClientResponse);
    }

    @Test(description = "Test case for getAccessRequest method.")
    public void testGetAccessRequest() throws Exception {
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString()))
                .thenReturn(new OAuthClientRequest.TokenRequestBuilder("/token"));
        OAuthClientRequest accessRequest = Whitebox
                .invokeMethod(amazonAuthenticator, "getAccessRequest", "/token", "dummy-clientId", "dummy-code",
                        "dummy-secret", "/callback");
        org.testng.Assert.assertNotNull(accessRequest);
        org.testng.Assert.assertEquals(accessRequest.getLocationUri(), "/token");
    }

    @Test(description = "Test case for getClaimDialectURI method")
    public void testGetClaimDialectURI() {
        String claimDialectURI = amazonAuthenticator.getClaimDialectURI();
        Assert.assertEquals(AmazonAuthenticatorConstants.CLAIM_DIALECT_URI, claimDialectURI);
    }

    @Test(description = "Test case for processAuthenticationResponse failed", dataProvider = "authenticatorProperties")
    public void testGetSubjectAttributes(Map<String, String> authenticatorProperties) throws Exception {
        AmazonAuthenticator spyAuthenticator = PowerMockito.spy(new AmazonAuthenticator());
        Mockito.when(oAuthClientResponse.getParam("access_token")).thenReturn("dummytoken");
        PowerMockito.doReturn("{\"userid\":\"testuser\"}")
                .when(spyAuthenticator, "sendRequest", Mockito.anyString(), Mockito.anyString());
        Map<ClaimMapping, String> claimMappings = spyAuthenticator
                .getSubjectAttributes(oAuthClientResponse, authenticatorProperties);
        Assert.assertEquals(1, claimMappings.size());
        for (ClaimMapping claimMapping : claimMappings.keySet()) {
            Assert.assertEquals("http://wso2.org/amazon/claims/userid", claimMapping.getLocalClaim().getClaimUri());
            Assert.assertEquals("testuser", claimMappings.get(claimMapping));
        }
    }
}
