Product: WSO2 IS authenticator for Amazon
Pre-requisites:

- Maven 3.x
- Java 1.6 or above

Tested Platform: 

- UBUNTU 14.04
- WSO2 IS 5.1.0
- Java 1.7

Do the following:

1. Navigate to amazon-authenticator/org.wso2.carbon.identity.authenticator.amazon and build.

2. Place org.wso2.carbon.identity.authenticator jar into <IS_HOME>/repository/components/dropins.

3. Start the IS server and create Identity provider and service provider in IS via the IS console.