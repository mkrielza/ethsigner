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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
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
  private static final String ERROR_ACCESSING_TMP_FILE_MESSAGE = "Failed to access config file";
  private static final String ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to initialize key store";
  private static final String ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to access key store";

  private Provider provider = null;
  private KeyStore keyStore = null;

  public HSMKeyStoreProvider(final String library, final String slot, final String pin) {
    File tmpConfigFile = null;
    try {
      tmpConfigFile = File.createTempFile("pkcs11-", ".cfg");
    } catch (IOException ex) {
      LOG.debug(ERROR_CREATING_TMP_FILE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_CREATING_TMP_FILE_MESSAGE, ex);
    }
    tmpConfigFile.deleteOnExit();
    PrintWriter configWriter = null;
    try {
      configWriter =
          new PrintWriter(
              new BufferedWriter(
                  new OutputStreamWriter(
                      new FileOutputStream(tmpConfigFile), Charset.defaultCharset())),
              true);
    } catch (FileNotFoundException ex) {
      LOG.debug(ERROR_ACCESSING_TMP_FILE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_TMP_FILE_MESSAGE, ex);
    }
    configWriter.println(String.format("name=%s", "HSM"));
    configWriter.println(String.format("library=%s", library));
    configWriter.println(String.format("slot=%s", slot));
    configWriter.println("attributes(generate, *, *) = { CKA_TOKEN = true }");
    configWriter.println("attributes(generate, CKO_CERTIFICATE, *) = { CKA_PRIVATE=false }");
    configWriter.println("attributes(generate, CKO_PUBLIC_KEY, *) = { CKA_PRIVATE=false }");
    configWriter.close();
    String configName = tmpConfigFile.getAbsolutePath();

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
      keyStore.load(null, pin.toCharArray());
    } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
      LOG.debug(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    LOG.debug("Successfully initialized slot");
  }

  public KeyStore getKeyStore() {
    return keyStore;
  }

  public Provider getProvider() {
    return provider;
  }
}
