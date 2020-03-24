/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.ethsigner.signer.hsm;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HSMKeyStoreProvider {

  private static final Logger LOG = LogManager.getLogger();
  private static final String ERROR_CREATING_TMP_FILE_MESSAGE =
      "Failed to create a temp config file";
  private static final String ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to initialize key store";
  private static final String ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to access key store";

  private Provider provider;
  private KeyStore keyStore;
  private String configName;
  private String slotIndex;
  private String slotPin;

  public HSMKeyStoreProvider(final String library, final String slot, final String pin) {
    final StringBuilder sb = new StringBuilder();
    sb.append(String.format("name = %s\n", "HSM"));
    sb.append(String.format("library = %s\n", library));
    sb.append(String.format("slot = %s\n", slot));
    sb.append("attributes(generate, *, *) = { CKA_TOKEN = true }\n");
    sb.append("attributes(generate, CKO_CERTIFICATE, *) = { CKA_PRIVATE=false }\n");
    sb.append("attributes(generate, CKO_PUBLIC_KEY, *) = { CKA_PRIVATE=false }\n");
    final String configContent = sb.toString();
    try {
      Path configPath = Files.createTempFile("pkcs11-", ".cfg");
      File configFile = configPath.toFile();
      configName = configFile.getAbsolutePath();
      configFile.deleteOnExit();
      Files.write(configPath, configContent.getBytes(Charset.defaultCharset()));
    } catch (IOException ex) {
      LOG.debug(ERROR_CREATING_TMP_FILE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_CREATING_TMP_FILE_MESSAGE, ex);
    }
    slotIndex = slot;
    slotPin = pin;
  }

  private void initialize() throws HSMKeyStoreInitializationException {
    Provider prototype = Security.getProvider("SunPKCS11");
    provider = prototype.configure(configName);
    try {
      keyStore = KeyStore.getInstance("PKCS11", provider);
    } catch (KeyStoreException ex) {
      LOG.debug(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    try {
      keyStore.load(null, slotPin.toCharArray());
    } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
      LOG.debug(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    LOG.debug("Successfully initialized hsm slot");
  }

  public KeyStore getKeyStore() {
    if (keyStore == null) initialize();
    return keyStore;
  }

  public Provider getProvider() {
    if (provider == null) initialize();
    return provider;
  }

  public String getSlotIndex() {
    return slotIndex;
  }
}
