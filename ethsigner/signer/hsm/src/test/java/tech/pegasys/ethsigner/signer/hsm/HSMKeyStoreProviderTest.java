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

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class HSMKeyStoreProviderTest {

  public static String library = "/usr/local/lib/softhsm/libsofthsm2.so";
  public static String slot = "992881475";
  public static String pin = "us3rs3cur3";

  @BeforeAll
  public static void setup() {}

  @Test
  public void eccDemoTest() {
    HSMKeyStoreProvider ksp = new HSMKeyStoreProvider(library, slot, pin);
    Provider p = ksp.getProvider();
    KeyStore ks = ksp.getKeyStore();
    try {
      eccDemo(p, ks, "SHA256withECDSA", "secp256k1");
      //eccDemo(p, ks, "SHA256withECDSA", "secp256r1");
      //eccDemo(p, ks, "SHA256withECDSA", "secp384r1");
    } catch (Exception ex) {
      System.out.println(ex.getMessage());
    }
  }

  private static void eccDemo(Provider p, KeyStore ks, String algo, String curve) throws Exception {
    System.out.println("Testing curve " + curve);

    String alias = "example_alias";
    // Delete previous test entry.
    ks.deleteEntry(alias);

    // Generate an EC key pair making use of the provider to force generation on the HSM instead of software.
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", p);
    ECGenParameterSpec kpgpars = new ECGenParameterSpec(curve);
    keyPairGenerator.initialize(kpgpars);
    System.out.println("Generating key pair");
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Create a self-signed (using the HSM) certificate to store with the public key. This is a java keystore requirement.
    System.out.println("Creating self signed certificate");
    X509Certificate cert = generateCert(keyPair, 1, "SHA256withECDSA", "CN=example, L=CT, C=ZA", null);
    ks.setKeyEntry(alias, keyPair.getPrivate(), null, new X509Certificate[] {cert});

    // Sign some data
    Signature sig = Signature.getInstance(algo, p);
    sig.initSign(keyPair.getPrivate());
    byte[] data = "test".getBytes(Charset.defaultCharset());
    sig.update(data);
    byte[] s = sig.sign();
    System.out.println("Signed with hardware key");

    // Verify the signature
    sig.initVerify(keyPair.getPublic());
    sig.update(data);
    if (!sig.verify(s)) {
      throw new Exception("signature did not verify");
    }
    System.out.println("Verified with hardware key.");
  }

  private static X509Certificate generateCert(
    KeyPair pair, int days, String algorithm, String dn, String provider) throws Exception {
    X500Name issuerName = new X500Name(dn);

    BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt()).abs();
    Calendar calendar = Calendar.getInstance();
    Date startDate = new Date();
    calendar.setTime(startDate);
    calendar.add(Calendar.DAY_OF_YEAR, days);

    Date endDate = calendar.getTime();
    X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, startDate, endDate, issuerName, pair.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign
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
    ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate());

    JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
    if (provider != null) converter.setProvider(provider);
    X509Certificate cert = converter.getCertificate(builder.build(contentSigner));
    cert.checkValidity(new Date());
    cert.verify(pair.getPublic());
    return cert;
  }

}
