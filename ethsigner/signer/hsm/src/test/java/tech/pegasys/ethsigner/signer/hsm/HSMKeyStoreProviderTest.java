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
/*

class HSMKeyStoreProviderTest {

  private static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  private static String slot = "992881475";
  private static String pin = "us3rs3cur3";

  private HSMKeyStoreProvider ksp;
  private HSMKeyGenerator kgr;

  @BeforeEach
  void beforeEach() {
    ksp = new HSMKeyStoreProvider(library, slot, pin);
    kgr = new HSMKeyGenerator(ksp);
  }

  @Test
  void generateTest() {
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
      fail("Failed to retrieve private key handle");
    }
    assertThat(privateKeyEntry).isNotNull();
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    assertThat(privateKey).isNotNull();

    // Sign some data
    // Signature sig = Signature.getInstance("SHA256withECDSA", ksp.getProvider());
    // sig.initSign(privateKey);
    // byte[] data = "test".getBytes(Charset.defaultCharset());
    // sig.update(data);
    // byte[] s = sig.sign();
    // System.out.println("Signed with hardware key.");

    // Verify the signature
    // sig.initVerify(keyPair.getPublic());
    // sig.update(data);
    // if (!sig.verify(s)) {
    //  throw new Exception("Signature did not verify");
    // }
    // System.out.println("Verified with hardware key.");

  }

  @Test
  void getAllTest() {
    String address = kgr.generate();
    System.out.println("Generated: " + address);
    List<String> addresses = kgr.getAll();
    assertThat(addresses).isNotEmpty();
    for (String a : addresses) {
      System.out.println("Listed: " + a);
    }
  }
}
*/
