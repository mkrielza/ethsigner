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
  private final String keyVaultName;
  private final String address;
  private final String keyVersion;
  private final String clientId;
  private final String clientSecret;

  public HSMConfig(
      final String keyVaultName,
      final String keyName,
      final String keyVersion,
      final String clientId,
      final String clientSecret) {
    this.keyVaultName = keyVaultName;
    this.address = keyName;
    this.keyVersion = keyVersion;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  public String getKeyVaultName() {
    return keyVaultName;
  }

  public String getAddress() {
    return address;
  }

  public String getKeyVersion() {
    return keyVersion;
  }

  public String getClientId() {
    return clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public static class AzureConfigBuilder {

    private String keyVaultName;
    private String keyName;
    private String keyVersion;
    private String clientId;
    private String clientSecret;

    public AzureConfigBuilder withKeyVaultName(final String keyVaultName) {
      this.keyVaultName = keyVaultName;
      return this;
    }

    public AzureConfigBuilder withKeyName(final String keyName) {
      this.keyName = keyName;
      return this;
    }

    public AzureConfigBuilder withKeyVersion(final String keyVersion) {
      this.keyVersion = keyVersion;
      return this;
    }

    public AzureConfigBuilder withClientId(final String clientId) {
      this.clientId = clientId;
      return this;
    }

    public AzureConfigBuilder withClientSecret(String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public HSMConfig build() {
      checkNotNull(keyVaultName, "Key Vault Name was not set.");
      checkNotNull(keyName, "Key Name was not set.");
      checkNotNull(keyVersion, "Key Version was not set.");
      checkNotNull(clientId, "Client Id was not set.");
      checkNotNull(clientSecret, "Client Secret was not set.");

      return new HSMConfig(keyVaultName, keyName, keyVersion, clientId, clientSecret);
    }
  }
}
