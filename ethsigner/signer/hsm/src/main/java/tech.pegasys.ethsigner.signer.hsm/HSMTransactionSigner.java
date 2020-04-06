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

public class HSMTransactionSigner implements TransactionSigner {

  // private static final Logger LOG = LogManager.getLogger();

  private final HSMWallet wallet;
  private final String address;

  public HSMTransactionSigner(final HSMWallet wallet, String address) {
    this.wallet = wallet;
    this.address = address;
  }

  @Override
  public Signature sign(final byte[] data) {
    return wallet.sign(data, address);
  }

  @Override
  public String getAddress() {
    return address;
  }
}
