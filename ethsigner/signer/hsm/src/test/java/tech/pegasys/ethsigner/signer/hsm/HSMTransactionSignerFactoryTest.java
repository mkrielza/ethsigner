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

import tech.pegasys.ethsigner.core.signing.TransactionSigner;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class HSMTransactionSignerFactoryTest {

  private static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  private static String slot = "WALLET-001";
  private static String pin = "us3rs3cur3";
  private static String address;

  private static HSMTransactionSignerFactory factory;

  @BeforeAll
  public static void beforeAll() {
    factory = new HSMTransactionSignerFactory(library, slot, pin);
    factory.initialize();
    address = factory.getWallet().generate();
  }

  @AfterAll
  public static void afterAll() {
    factory.shutdown();
  }

  @Test
  public void success() {
    final TransactionSigner signer = factory.createSigner(address);
    assertThat(signer).isNotNull();
    assertThat(signer.getAddress()).isNotEmpty();
    assertThat(signer.getAddress()).isEqualTo(address);
  }
}
