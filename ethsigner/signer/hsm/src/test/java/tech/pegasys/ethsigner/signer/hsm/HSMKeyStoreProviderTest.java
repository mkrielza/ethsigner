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

public class HSMKeyStoreProviderTest {

  public static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  public static String slot = "992881475";
  public static String pin = "us3rs3cur3";


  @BeforeAll
  public static void setup() {}

  @Test
  public void generateKeyTest() {
    HSMKeyStoreProvider ksp = new HSMKeyStoreProvider(library, slot, pin);
    HSMKeyGenerator kgr = new HSMKeyGenerator(ksp);
    String address = kgr.generate();
    boolean exists = kgr.exists(address);
    List<String> addresses = kgr.getAll();

    KeyStore.PrivateKeyEntry privateKeyEntry = null;
    try {
      privateKeyEntry = (KeyStore.PrivateKeyEntry) ksp.getKeyStore().getEntry(address, null);
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
      //throw new Exception("Could not retrieve the key");
    }
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
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
}

/*
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

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
    byte[] data = "Hello Kitty".getBytes(Charset.defaultCharset());
    try {
      String address = generateKey(p, ks, "SHA256withECDSA", "secp256k1");
      HSMTransactionSigner signer = new HSMTransactionSigner(ksp, address);
      System.out.println("Signature: " + signer.sign(data).toString());

      // eccDemo(p, ks, "SHA256withECDSA", "secp256r1");
      // eccDemo(p, ks, "SHA256withECDSA", "secp384r1");
    } catch (Exception ex) {
      System.out.println(ex.getMessage());
    }

    //    try {
    //      ks.deleteEntry("example1_test");
    //    } catch (KeyStoreException e) {
    //      System.out.println(e.getMessage());
    //    }
  }

  private static String generateKey(Provider p, KeyStore ks, String algo, String curve)
      throws Exception {
    System.out.println("Testing curve " + curve);

    // Generate an EC key pair using the provider to force generation on the HSM instead of
    // software.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", p);
    ECGenParameterSpec kpgparams = new ECGenParameterSpec(curve);
    keyPairGenerator.initialize(kpgparams);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Create a self-signed certificate to store with the public key.
    // This is a java keystore requirement. The certificate is signed using the HSM.
    X509Certificate cert = generateCert(keyPair, 1, algo, "CN=EthSigner, L=CT, C=ZA", p);
    String alias = generateAddr(keyPair, curve);
    ks.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[] {cert});
    System.out.println("Generated key pair with address " + alias);

    // Sign some data
    Signature sig = Signature.getInstance(algo, p);
    sig.initSign(keyPair.getPrivate());
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

    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    System.out.println("Successfully retrieved private key handle: " + privateKey);
    for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements(); ) {
      String a = aliases.nextElement();
      System.out.println("Successfully enumerated alias: " + a);
    }

    return alias;
  }

  private static String generateAddr(KeyPair keyPair, String curve) {
    final ECPoint w = ((ECPublicKey) keyPair.getPublic()).getW();
    final BigInteger x = w.getAffineX();
    final BigInteger y = w.getAffineY();
    X9ECParameters params = SECNamedCurves.getByName(curve);
    ECDomainParameters ec =
        new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
    byte[] publicKey = ec.getCurve().createPoint(x, y).getEncoded(false);
    return Keys.toChecksumAddress(Keys.getAddress(Sign.publicFromPoint(publicKey)));
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
