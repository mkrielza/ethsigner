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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Hash;
import tech.pegasys.ethsigner.core.signing.TransactionSigner;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class HSMCryptoProviderTest {

  private static final Logger LOG = LogManager.getLogger();

  private static HSMCryptoProvider ksp;
  private static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  private static long slot = 2059091075;
  private static String pin = "us3rs3cur3";
  private static String address = "0x47374Ed3355101C178777F945DBB409a60863e8E";

  @BeforeAll
  public static void createProvider() {
    ksp = new HSMCryptoProvider(library);
  }

  @Test
  public void success() {
    final byte[] data = {1, 2, 3};
    final byte[] hash = Hash.sha3(data);
    try {
      ksp.initialize();
      ksp.login(slot, pin);
      ksp.getAll(slot);
      ksp.sign(slot, hash, address);
    } catch (Exception ex) {
      LOG.error(ex);
    } finally {
      ksp.shutdown();
    }
  }
}
