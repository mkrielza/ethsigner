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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class HSMKeyStoreProviderTest {

  public static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  public static String slot = "992881475";
  public static String pin = "us3rs3cur3";


  @BeforeAll
  public static void setup() {}

  @Test
  public void generateTest() {
    HSMKeyStoreProvider ksp = new HSMKeyStoreProvider(library, slot, pin);
    HSMKeyGenerator kgr = new HSMKeyGenerator(ksp);
    String address = kgr.generate();
    System.out.println("Generated: " + address);
    boolean exists = kgr.exists(address);
    assertThat(exists).isTrue();
    List<String> addresses = kgr.getAll();
    assertThat(addresses).contains(address);
    KeyStore.PrivateKeyEntry privateKeyEntry = null;
    try {
      privateKeyEntry = (KeyStore.PrivateKeyEntry) ksp.getKeyStore().getEntry(address, null);
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
    }
    assertThat(privateKeyEntry).isNotNull();
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    assertThat(privateKey).isNotNull();
    /*
    // Sign some data
    Signature sig = Signature.getInstance("SHA256withECDSA", ksp.getProvider());
    sig.initSign(privateKey);
    byte[] data = "test".getBytes(Charset.defaultCharset());
    sig.update(data);
    byte[] s = sig.sign();
    System.out.println("Signed with hardware key.");

    // Verify the signature
    sig.initVerify(keyPair.getPublic());
    sig.update(data);
    if (!sig.verify(s)) {
      throw new Exception("Signature did not verify");
    }
    System.out.println("Verified with hardware key.");
    */
  }
  @Test
  public void getAllTest() {
    HSMKeyStoreProvider ksp = new HSMKeyStoreProvider(library, slot, pin);
    HSMKeyGenerator kgr = new HSMKeyGenerator(ksp);
    String address = kgr.generate();
    System.out.println("Generated: " + address);
    List<String> addresses = kgr.getAll();
    assertThat(addresses).isNotEmpty();
    for (String a : addresses) {
      System.out.println("Listed: " + a);
    }
  }
}
