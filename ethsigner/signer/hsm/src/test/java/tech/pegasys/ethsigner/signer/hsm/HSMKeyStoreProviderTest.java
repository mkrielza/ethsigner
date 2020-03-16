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

public class HSMKeyStoreProviderTest {

  public static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  public static String slot = "992881475";
  public static String pin = "us3rs3cur3";

  @BeforeAll
  public static void setup() {}

  @Test
  public void generateKeyTest() {
    HSMKeyStoreProvider ksp = new HSMKeyStoreProvider(library, slot, pin);
    Provider p = ksp.getProvider();
    KeyStore ks = ksp.getKeyStore();
    try {
      generateKey(p, ks, "SHA256withECDSA", "secp256k1");
      // eccDemo(p, ks, "SHA256withECDSA", "secp256r1");
      // eccDemo(p, ks, "SHA256withECDSA", "secp384r1");
    } catch (Exception ex) {
      System.out.println(ex.getMessage());
    }
  }

  private static void generateKey(Provider p, KeyStore ks, String algo, String curve)
      throws Exception {
    System.out.println("Testing curve " + curve);

    String alias = "alias";
    // Delete previous test entry.
    ks.deleteEntry(alias);

    // Generate an EC key pair using the provider to force generation on the HSM instead of
    // software.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", p);
    ECGenParameterSpec kpgparams = new ECGenParameterSpec(curve);
    keyPairGenerator.initialize(kpgparams);
    System.out.println("Generating key pair.");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Create a self-signed certificate to store with the public key. This is a java keystore
    // requirement. The certificate is signed using the HSM
    System.out.println("Creating self signed certificate.");
    X509Certificate cert = generateCert(keyPair, 1, algo, "CN=EthSigner, L=CT, C=ZA", p);
    ks.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[] {cert});

    // sign some data
    Signature sig = Signature.getInstance(algo, p);
    sig.initSign(keyPair.getPrivate());
    byte[] data = "test".getBytes(Charset.defaultCharset());
    sig.update(data);
    byte[] s = sig.sign();
    System.out.println("Signed with hardware key.");

    // verify the signature
    sig.initVerify(keyPair.getPublic());
    sig.update(data);
    if (!sig.verify(s)) {
      throw new Exception("Signature did not verify");
    }
    System.out.println("Verified with hardware key.");

    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    System.out.println("Successfully retrieved private key handle: " + privateKey);
    for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements(); ) {
      String a = aliases.nextElement();
      System.out.println("Successfully enumerated alias: " + a);
    }
  }

  private static X509Certificate generateCert(
      KeyPair pair, int days, String algorithm, String dn, Provider p) throws Exception {
    X500Name issuerName = new X500Name(dn);

    BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt()).abs();
    Calendar calendar = Calendar.getInstance();
    Date startDate = new Date();
    calendar.setTime(startDate);
    calendar.add(Calendar.DAY_OF_YEAR, days);

    Date endDate = calendar.getTime();
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerName, serial, startDate, endDate, issuerName, pair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    KeyUsage usage =
        new KeyUsage(
            KeyUsage.keyCertSign
                | KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment
                | KeyUsage.cRLSign);
    builder.addExtension(Extension.keyUsage, false, usage);

    ASN1EncodableVector purposes = new ASN1EncodableVector();
    purposes.add(KeyPurposeId.id_kp_serverAuth);
    purposes.add(KeyPurposeId.id_kp_clientAuth);
    purposes.add(KeyPurposeId.anyExtendedKeyUsage);
    builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
    ContentSigner contentSigner =
        new JcaContentSignerBuilder(algorithm).setProvider(p).build(pair.getPrivate());

    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    X509Certificate cert = converter.getCertificate(builder.build(contentSigner));
    cert.checkValidity(new Date());
    cert.verify(pair.getPublic());
    return cert;
  }
}
*/
