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

import static com.google.common.base.Preconditions.checkNotNull;

public class HSMConfig {
  private final String address;
  private final String slotIndex;

  public HSMConfig(final String address, final String slotIndex) {

    this.address = address;
    this.slotIndex = slotIndex;
  }

  public String getAddress() {
    return address;
  }

  public String getSlotIndex() {
    return slotIndex;
  }

  public static class HSMConfigBuilder {
    private String address;
    private String slotIndex;

    public HSMConfigBuilder withAddress(final String keyName) {
      this.address = keyName;
      return this;
    }

    public HSMConfigBuilder withSlotIndex(final String keyVersion) {
      this.slotIndex = keyVersion;
      return this;
    }

    public HSMConfig build() {
      checkNotNull(address, "Address was not set.");
      checkNotNull(slotIndex, "Slot index was not set.");

      return new HSMConfig(address, slotIndex);
    }
  }
}
