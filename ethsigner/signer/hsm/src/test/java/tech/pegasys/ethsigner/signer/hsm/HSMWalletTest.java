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

import tech.pegasys.ethsigner.core.signing.Signature;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Hash;

public class HSMWalletTest {

  private static final Logger LOG = LogManager.getLogger();

  private static HSMCrypto c;
  private static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  private static long slot = 2059091075;
  private static String pin = "us3rs3cur3";

  @BeforeAll
  public static void beforeAll() {
    c = new HSMCrypto(library);
    c.initialize();
  }

  @AfterAll
  public static void afterAll() {
    c.shutdown();
  }

  @Test
  public void generate() {
    try {
      HSMWallet w = new HSMWallet(c, slot, "");
      boolean opened = w.open(pin);
      LOG.info("Opened: " + opened);
      String address = w.generate();
      LOG.info("Address: " + address);
      boolean contains = w.contains(address);
      LOG.info("Contains: " + contains);
      boolean closed = w.close();
      LOG.info("Closed: " + closed);
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  @Test
  public void sign() {
    final byte[] data = {1, 2, 3};
    final byte[] hash = Hash.sha3(data);
    try {
      HSMWallet w = new HSMWallet(c, slot, "");
      boolean opened = w.open(pin);
      LOG.info("Opened: " + opened);
      String address = w.generate();
      assertThat(address).isNotNull();
      LOG.info("Address: " + address);
      Signature sig = w.sign(hash, address);
      assertThat(sig).isNotNull();
      boolean closed = w.close();
      LOG.info("Closed: " + closed);
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  @Test
  public void clear() {
    try {
      HSMWallet w = new HSMWallet(c, slot, "");
      boolean opened = w.open(pin);
      LOG.info("Opened: " + opened);
      boolean cleared = w.clear();
      LOG.info("Cleared: " + cleared);
      boolean closed = w.close();
      LOG.info("Closed: " + closed);
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }
}
