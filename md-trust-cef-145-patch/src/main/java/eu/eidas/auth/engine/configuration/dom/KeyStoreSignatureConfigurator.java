/* 
#   Copyright (c) 2017 European Commission  
#   Licensed under the EUPL, Version 1.2 or – as soon they will be 
#   approved by the European Commission - subsequent versions of the 
#    EUPL (the "Licence"); 
#    You may not use this work except in compliance with the Licence. 
#    You may obtain a copy of the Licence at: 
#    * https://joinup.ec.europa.eu/page/eupl-text-11-12  
#    *
#    Unless required by applicable law or agreed to in writing, software 
#    distributed under the Licence is distributed on an "AS IS" basis, 
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
#    See the Licence for the specific language governing permissions and limitations under the Licence.
 */
package eu.eidas.auth.engine.configuration.dom;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;

import com.google.common.collect.ImmutableSet;

import org.apache.commons.lang.StringUtils;

import eu.eidas.auth.engine.configuration.SamlEngineConfigurationException;
import eu.eidas.auth.engine.core.impl.CertificateValidator;
import se.idsec.eidas.cef.trustconfig.EidasTrustedCertificates;

import javax.annotation.Nullable;

/**
 * KeyStore-based SignatureConfigurator.
 *
 * @since 1.1
 */
public final class KeyStoreSignatureConfigurator {

    private static final String PROPERTY_PREFIX_DEFAULT = "";
    /**
     * This is a customized object which append the trusted certificate list with certificates hold in a PEM file
     * The location of the PEM file is determined by the environment variable "EIDAS_TRUSTED_CERTS_FILE".
     * This file can hold 1 or more trusted certificates.
     */
    private static final EidasTrustedCertificates externalTrustConfig = new EidasTrustedCertificates();

    private KeyStore.PrivateKeyEntry getPrivateSigningKeyAndCertificate(Map<String, String> properties,
                                                                        String propertyPrefix,
                                                                        String defaultSerialNumber,
                                                                        String defaultIssuer,
                                                                        @Nullable String defaultPath)
            throws SamlEngineConfigurationException {
        String propPrefix = PROPERTY_PREFIX_DEFAULT;
        if (StringUtils.isNotEmpty(propertyPrefix)) {
            propPrefix = propertyPrefix;
        }
        String serialNumber = properties.get(propPrefix + SignatureKey.SERIAL_NUMBER.getKey());
        if (StringUtils.isBlank(serialNumber)) {
            serialNumber = defaultSerialNumber;
        }
        String issuer = properties.get(propPrefix + SignatureKey.ISSUER.getKey());
        if (StringUtils.isBlank(issuer)) {
            issuer = defaultIssuer;
        }

        String keyStorePathConfigurationKey = propPrefix + KeyStoreKey.KEYSTORE_PATH.getKey();
        if (!properties.containsKey(keyStorePathConfigurationKey)) {
            keyStorePathConfigurationKey = KeyStoreKey.KEYSTORE_PATH.getKey();
        }

        String keyStoreTypeConfigurationKey = propPrefix + KeyStoreKey.KEYSTORE_TYPE.getKey();
        if (!properties.containsKey(keyStoreTypeConfigurationKey)) {
            keyStoreTypeConfigurationKey = KeyStoreKey.KEYSTORE_TYPE.getKey();
        }

        String keyStoreProviderConfigurationKey = propPrefix + KeyStoreKey.KEYSTORE_PROVIDER.getKey();
        if (!properties.containsKey(keyStoreProviderConfigurationKey)) {
            keyStoreProviderConfigurationKey = KeyStoreKey.KEYSTORE_PROVIDER.getKey();
        }

        String keyStorePasswordConfigurationKey = propPrefix + KeyStoreKey.KEYSTORE_PASSWORD.getKey();
        if (!properties.containsKey(keyStorePasswordConfigurationKey)) {
            keyStorePasswordConfigurationKey = KeyStoreKey.KEYSTORE_PASSWORD.getKey();
        }

        String keyAliasConfigurationKey = propPrefix + KeyStoreKey.KEY_ALIAS.getKey();
        if (!properties.containsKey(keyAliasConfigurationKey)) {
            keyAliasConfigurationKey = KeyStoreKey.KEY_ALIAS.getKey();
        }

        String keyPasswordConfigurationKey = propPrefix + KeyStoreKey.KEY_PASSWORD.getKey();
        if (!properties.containsKey(keyPasswordConfigurationKey)) {
            keyPasswordConfigurationKey = KeyStoreKey.KEY_PASSWORD.getKey();
        }

        KeyStoreConfigurator.KeyStoreConfigurationKeys keyStoreConfigurationKeys =
                new KeyStoreConfigurator.KeyStoreConfigurationKeys(keyStorePathConfigurationKey,
                                                                   keyStoreTypeConfigurationKey,
                                                                   keyStoreProviderConfigurationKey,
                                                                   keyStorePasswordConfigurationKey,
                                                                   keyAliasConfigurationKey,
                                                                   keyPasswordConfigurationKey);

        return new KeyStoreConfigurator(properties, keyStoreConfigurationKeys, defaultPath).loadPrivateKeyEntry(serialNumber,
                                                                                                   issuer);
    }

    public SignatureConfiguration getSignatureConfiguration(Map<String, String> properties, @Nullable String defaultPath)
            throws SamlEngineConfigurationException {
        boolean checkedValidityPeriod = CertificateValidator.isCheckedValidityPeriod(properties);
        boolean disallowedSelfSignedCertificate = CertificateValidator.isDisallowedSelfSignedCertificate(properties);
        boolean responseSignAssertions = Boolean.parseBoolean(
                StringUtils.trim(SignatureKey.RESPONSE_SIGN_ASSERTIONS.getAsString(properties)));

        String serialNumber = SignatureKey.SERIAL_NUMBER.getAsString(properties);
        String issuer = SignatureKey.ISSUER.getAsString(properties);
        KeyStoreContent keyStoreContent = new KeyStoreConfigurator(properties, defaultPath).loadKeyStoreContent();
        KeyStore.PrivateKeyEntry signatureKeyAndCertificate =
                keyStoreContent.getMatchingPrivateKeyEntry(serialNumber, issuer);
        ImmutableSet<X509Certificate> trustedCertificates = keyStoreContent.getCertificates();

        /*
         * Customized addition by SE for injecting trusted MDSL and PEM certificates
         */
        trustedCertificates = externalTrustConfig.addTrustedCertificates(trustedCertificates, properties);

        String signatureAlgorithmWhiteListStr = SignatureKey.SIGNATURE_ALGORITHM_WHITE_LIST.getAsString(properties);
        String signatureAlgorithm = SignatureKey.SIGNATURE_ALGORITHM.getAsString(properties);
        KeyStore.PrivateKeyEntry metadataSigningKeyAndCertificate =
                getPrivateSigningKeyAndCertificate(properties, SignatureKey.METADATA_PREFIX.getKey(), serialNumber,
                                                   issuer, defaultPath);

        return new SignatureConfiguration(checkedValidityPeriod, disallowedSelfSignedCertificate, responseSignAssertions,
                                          signatureKeyAndCertificate, trustedCertificates, signatureAlgorithm,
                                          signatureAlgorithmWhiteListStr, metadataSigningKeyAndCertificate);
    }
}
