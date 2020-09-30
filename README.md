# Flowable Keycloak integration library

This library allows to replace Flowable IDM with Keycloak integration (through OpenID Connect) to the 
Flowable Apps (https://flowable.com/open-source/docs/bpmn/ch14-Applications/).

## Maven project
![Maven Central](https://img.shields.io/maven-central/v/com.premiumminds.flowable/flowable-keycloak)

Add the following maven dependency to your project `pom.xml`:

```xml
<dependency>
   <groupId>com.premiumminds.flowable</groupId>
   <artifactId>flowable-keycloak</artifactId>
   <version>1.6</version>
</dependency>
```
Check out [sonatype repository](https://oss.sonatype.org/index.html#nexus-search;quick~flowable-keycloak) for latest snapshots and releases.

## Example usage

This example works for the flowable-ui-* projects in the flowable repository:

* [Flowable UI Admin](https://github.com/flowable/flowable-engine/tree/master/modules/flowable-ui-admin)
* [Flowable UI Modeler](https://github.com/flowable/flowable-engine/tree/master/modules/flowable-ui-modeler)
* [Flowable UI Task](https://github.com/flowable/flowable-engine/tree/master/modules/flowable-ui-task)

### Changes in the project

Add the `flowable-keycloak` library to the POM of the `flowable-ui-*-conf` project.

Changes in the `SecurityConfiguration` class in the `flowable-ui-*-conf` project:

* Replace the class `FlowableCookieFilterRegistrationBean` with `KeycloakCookieFilterRegistrationBean`

### Configurations

This library reads the following configurations:

```
keycloak.url = <keycloak url>
keycloak.realm = <realm>
keycloak.issuer-url = <realm url, usually something like: http://example.com/auth/realms/mycompany>
keycloak.client.client-id = <client id>
keycloak.client.client-secret = <client secret>
keycloak.client.scope = openid roles
keycloak.client.redirect-uri = ${flowable.common.app.redirect-on-auth-success}/callback 
keycloak.connect-timeout = 10000
keycloak.read-timeout = 10000
```

For testing, you can add this configurations to the file 
`src/main/resources/flowable-default.properties` in the "flowable-ui-*-app" project.

### Keycloak roles

The library will add the client roles as flowable priviledges.

Flowable uses the following priviledges:

* `access-modeler`
* `access-rest-api`
* `access-admin`
* `access-task`

So you should have this as client roles in keycloak instance.

## Continuous Integration

[![Build Status](https://travis-ci.org/premium-minds/flowable-keycloak.png?branch=master)](https://travis-ci.org/premium-minds/flowable-keycloak)

CI is hosted by [travis-ci.org](https://travis-ci.org/)

## Licence

Copyright (C) 2020 [Premium Minds](https://www.premium-minds.com/)

Licensed under the [GNU Lesser General Public Licence](https://www.gnu.org/licenses/lgpl.html)