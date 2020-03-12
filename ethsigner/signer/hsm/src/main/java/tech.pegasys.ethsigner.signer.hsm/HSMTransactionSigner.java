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

import tech.pegasys.ethsigner.core.signing.Signature;
import tech.pegasys.ethsigner.core.signing.TransactionSigner;

import java.security.KeyStore;

public class HSMTransactionSigner implements TransactionSigner {

  private final HSMKeyStoreProvider provider;
  private final String address;

  public HSMTransactionSigner(final HSMKeyStoreProvider provider, String address) {
    this.provider = provider;
    this.address = address;
  }

  @Override
  public Signature sign(final byte[] data) {
    KeyStore keyStore = provider.getKeyStore();
    System.out.println(keyStore.getType());
    //    final SignatureData signature = Sign.signMessage(data, credentials.getEcKeyPair());
    //    return new Signature(
    //        new BigInteger(signature.getV()),
    //        new BigInteger(signature.getR()),
    //        new BigInteger(signature.getS()));
    return null;
  }

  @Override
  public String getAddress() {
    return address;
  }
}
