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

import tech.pegasys.ethsigner.core.signing.Signature;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HSMWallet {

  private static final Logger LOG = LogManager.getLogger();

  private final HSMCrypto crypto;
  private final long slotIndex;
  private final String slotLabel;
  // private final boolean bip32;

  public HSMWallet(HSMCrypto crypto, long slotIndex, String slotLabel) {
    this.crypto = crypto;
    this.slotIndex = slotIndex;
    this.slotLabel = slotLabel;
    // this.bip32 = bip32;
  }

  public String getStatus() {
    boolean isLoggedIn = crypto.isLoggedIn(slotIndex);
    return isLoggedIn ? "Open" : "Closed";
  }

  public String getLabel() {
    return slotLabel;
  }

  public boolean open(String slotPin) {
    if (slotPin.isEmpty()) {
      LOG.error("HSM Pin is needed");
      return false;
    }
    return crypto.login(slotIndex, slotPin);
    // if (bip32)
    // crypto.DeriveBIP32MasterKeys(slotIndex); // Derive the BIP32 master seed and master key pair
    // in the HSM.
  }

  public boolean close() {
    if (crypto.isLoggedIn(slotIndex)) {
      return crypto.logout(slotIndex);
    }
    return false;
  }

  public List<String> getAddresses() {
    return crypto.getAddresses(slotIndex);
  }

  public boolean contains(String address) {
    return crypto.containsAddress(slotIndex, address);
  }

  public boolean clear() {
    boolean result = true;
    List<String> addresses = crypto.getAddresses(slotIndex);
    for (String address : addresses) {
      result = result && crypto.deleteECKeyPair(slotIndex, address);
    }
    return result;
  }

  public String generate() {
    return crypto.generateECKeyPair(slotIndex);
  }

  public Signature sign(byte[] hash, String address) {
    return crypto.sign(slotIndex, hash, address);
  }
}
