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

  private final HSMCrypto crypto;
  private final HSMWallet wallet;

  private final long slotIndex;
  private final String slotPin;
  private boolean initialized = false;

  public HSMTransactionSignerFactory(String library, String slotIndex, String slotPin) {
    this.slotIndex = Long.parseLong(slotIndex);
    this.slotPin = slotPin;
    crypto = new HSMCrypto(library);
    wallet = new HSMWallet(this.crypto, this.slotIndex, "");
  }

  public void initialize() {
    crypto.initialize();
    wallet.open(slotPin);
    initialized = true;
  }

  public void shutdown() {
    wallet.close();
    crypto.shutdown();
    initialized = false;
  }

  public HSMWallet getWallet() {
    return wallet;
  }

  public String getSlotIndex() {
    return Long.toString(slotIndex);
  }

  public TransactionSigner createSigner(String address) {
    if (!initialized) initialize();
    return new HSMTransactionSigner(wallet, address);
  }
}
