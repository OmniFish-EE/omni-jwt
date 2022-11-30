# OmniFaces JWT
JWT implementation for [Jakarta EE](https://jakarta.ee)

OmniFaces JWT is a [compatible implementation](https://wiki.eclipse.org/MicroProfile/Implementation#MP_JWT_implementations) of [MicroProfile JWT AUTH](https://microprofile.io/project/eclipse/microprofile-jwt-auth) 2.0.

It is derived from [Payara's implementation](https://github.com/payara/Payara/tree/master/appserver/payara-appserver-modules/microprofile/jwt-auth).

OmniFaces JWT can be used standalone on any runtime that supports Jakarta Security and CDI 2.0. It essentially installs a standard Jakarta authentication mechanism and identity store when the application contains a class annotated with the MP @LoginConfig annotation.

An example is provided in the [Piranha project](https://github.com/piranhacloud/piranha/tree/master/test/omnifaces-jwt).


Payara is a trademark of the Payara Foundation.
