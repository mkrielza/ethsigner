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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import tech.pegasys.ethsigner.core.signing.TransactionSigner;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class HSMKeystoreSignerTest {

  private static HSMKeyStoreProvider ksp;

  @BeforeAll
  public static void createProvider() {
    ksp = mock(HSMKeyStoreProvider.class);
  }

  @Test
  public void success() {
    final TransactionSigner signer = (new HSMKeystoreSignerFactory(ksp)).createSigner("0x");

    assertThat(signer).isNotNull();
    assertThat(signer.getAddress()).isNotEmpty();
  }
}
