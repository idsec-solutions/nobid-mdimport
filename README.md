<img height="100" src="img/nobid-full.svg"></img>

# NOBID Metadata import

This repo provides the source code for addding the capability of CEF eiDAS nodes to import trusted metadata certificates from one or more 
MetadataServiceList (MDSL) sources, providing signed and information about trusted metadata sources.

## Structure
The present source code builds amends the functionality of the existing `eidas-saml-engine` module of an existing eIDAS CEF node.

This is done by providing an altered version of the eu.eidas.auth.engine.configuration.dom.KeyStoreSignatureConfigurator` class that
replaces the original version of the class. This is achieved through the maven shade plugin.

One project module exist for every version of the CEF code where the module `md-trust-cef-240-path is the module to patch
the 2.4.0 version of the CEF eidas node.

## Build information
To build this project it is first necessary to build the original CEF eIDAS node sources of the desired version.
This is necessary to install the .jar of the original `eidas-saml-engine` module in the local maven repository.

To build all modules and versions of the patch simply build the maven project in the root directory:

> \> `mvn clean install`

To build only one particular version of the patch then build individually first following projects in the following order:

- md-trust-xml
- md-trust-core
- and finally the target version of the patch (such as md-trust-cef-240-patches)

All modules are build executing the `mvn clean install` command in the root directory of each module.

Once this is built, the `EIDAS-Node` module `pom.xml` file must be modified to use the new `eidas-saml-engine` module.

This is done by altering the following lines of code in the pom.xml file from:

        <dependency>
            <groupId>eu.eidas</groupId>
            <artifactId>eidas-saml-engine</artifactId>
        </dependency>


to: 

        <dependency>
            <groupId>se.idsec.eidas.cef</groupId>
            <artifactId>eidas-saml-engine-mdsl</artifactId>
            <version>2.4.0</version>
        </dependency>

NOTE: That the example here relates to the 2.4.0 version of the patch. Use the version of the desired CEF node patch.

Once this is done, then the CEF node can be rebuild using the normal maven command for building the CEF node. Please refer to the CEF manual
to determine the appropriate maven command used to build the CEF node for your particular environment.


