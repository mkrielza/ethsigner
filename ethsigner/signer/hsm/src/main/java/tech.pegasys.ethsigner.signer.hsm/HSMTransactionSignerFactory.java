/*
 * Copyright 2019 ConsenSys AG.
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

import tech.pegasys.ethsigner.core.signing.TransactionSigner;

public class HSMTransactionSignerFactory {

  // private static final Logger LOG = LogManager.getLogger();

  private final HSMKeyStoreProvider provider;

  public HSMTransactionSignerFactory(final HSMKeyStoreProvider provider) {
    this.provider = provider;
  }

  public TransactionSigner createSigner(String address) {
    //    final String password;
    //    try {
    //      password = readPasswordFromFile(passwordFilePath);
    //    } catch (final IOException e) {
    //      final String message = READ_PWD_FILE_MESSAGE;
    //      LOG.error(message, e);
    //      throw new TransactionSignerInitializationException(message, e);
    //    }
    //    try {
    //      final Credentials credentials = WalletUtils.loadCredentials(password,
    // keyFilePath.toFile());
    //      return new HSMTransactionSigner(credentials);
    //    } catch (final IOException e) {
    //      final String message = READ_AUTH_FILE_MESSAGE + keyFilePath.toString();
    //      LOG.error(message, e);
    //      throw new TransactionSignerInitializationException(message, e);
    //    } catch (final CipherException e) {
    //      final String message = DECRYPTING_KEY_FILE_MESSAGE;
    //      LOG.error(message, e);
    //      throw new TransactionSignerInitializationException(message, e);
    //    }

    return new HSMTransactionSigner(provider, address);
  }
}
