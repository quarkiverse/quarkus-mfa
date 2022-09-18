# Quarkus MFA (Multi-Factored Authentication)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

[![Version](https://img.shields.io/maven-central/v/io.quarkiverse.mfa/quarkus-mfa?logo=apache-maven&style=flat-square)](https://search.maven.org/artifact/io.quarkiverse.mfa/quarkus-mfa)

## Overview

A [Quarkus](https://quarkus.io/) extension that provides enhanced form based authentication. It provides strong native authentication to supplement the preferred [OIDC authentication mechanism](https://quarkus.io/guides/security-openid-connect-web-authentication). 

Centralized identity management should be goal of all organizations and OIDC should be the primary form of authentication for Quarkus web applications. Consider utilizing this authentication extension under these two circumstances:

1. No OIDC Identity Provider Available - Some organizations may not have an OIDC IDP to utlize or it may be impratical to provision and/or configure an IDP for a web application with a small population of workers.

2. Secure backdoor authentication - Native authentication directly into the web application may be necessary in case the OIDC IDP becomes unavailable. Also runtime delegated administration of the OIDC [multi-tenant](https://quarkus.io/guides/security-openid-connect-multitenancy) configuration could potentially lock users out of the application and the administrators would need a means to restore access.


## Features
The Quarkus MFA extension is similar to the built-in [form based authentication mechanism](https://quarkus.io/guides/security-built-in-authentication#form-auth) and it provides the following features:

* An encrypted cookie is used to track authentication state, similar to the form based authentication mechanism
* A [JWE](https://en.wikipedia.org/wiki/JSON_Web_Encryption) [JWT](https://en.wikipedia.org/wiki/JSON_Web_Token), similar to the OIDC ID Token except encrypted, is saved as a cookie and is used to track authentication state.
* As a user proceeds through the authentication flow the authentication context JWE is eventally upgraded to an authenticated session cookie, similar to the OIDC extension.
* Time Based One-Time Password ([TOTP](https://en.wikipedia.org/wiki/Time-based_one-time_password)) support
* Plugable [Identity Store](runtime/src/main/java/io/quarkiverse/mfa/runtime/MfaIdentityStore.java) implementations allow interactions with back-end Cloud database user stores
* Account Lock
* Password Reset
* TOTP QR Code Key Registration
* TOTP Passcode Validation
* Application provided login and log out presentation pages
* [MVC](https://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller) presentation support allowing views to be rendered based on the login state
* Single Page Application ([SPA](https://en.wikipedia.org/wiki/Single-page_application)) Support
    * The authentication [action controller](https://github.com/quarkiverse/quarkus-mfa/blob/ba64410474429891e9d58affe343028d2cb44c62/runtime/src/main/java/io/quarkus/mfa/runtime/MfaAuthenticationMechanism.java#L121) supports both HTML form encoding and JSON
    * SPAs can perform a GET request to obtain details about the current authentication state
    * Based on authentication state SPAs can post login attempts, password resets, or TOTP passcode validation requests and respond accordingly based on the result. 
    * The authentication context cookie gets updated identically to the forms based login mechanism


## Installation

1. Add the extension to the Quarkus web application's Maven pom.xml    

1. Create an [MFA Identity Store](runtime/src/main/java/io/quarkus/mfa/runtime/MfaIdentityStore.java) implementation. This [TestMfaIdentityStore.java](integration-tests/src/main/java/io/quarkus/mfa/it/TestMfaIdentityStore.java) example can be used as a reference.

1. Create login views or use SPA javascript to perform authentication actions. Please examine the HTML Forms and SPA examples in the [example project](example)
