
//import java.security.KeyStore;
//import java.security.Security;
//import java.security.Provider;
//import java.security.PublicKey;
//import java.security.PrivateKey;
//import java.security.SecureRandom;
//import java.security.KeyPairGenerator;
//import java.security.KeyPair;
//import java.security.Signature;
import java.security.cert.X509Certificate;
//import java.util.Base64;
//import java.util.Enumeration;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.security.KeyStore;
import java.security.Security;
import java.security.Provider;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Base64;

public class TestClass {

        public static char[] password = "us3rs3cur3".toCharArray();

        public static void main(String[] args) throws Exception {
            String configName = "/etc/softhsm/pkcs11.cfg";

            // Java 8
//        sun.security.pkcs11.SunPKCS11 provider = new sun.security.pkcs11.SunPKCS11(configName);
//        Security.addProvider(provider);
//
            // Java 11
            Provider prototype = Security.getProvider("SunPKCS11");
            Provider provider = prototype.configure(configName);

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, password);
            System.out.println("Successfully initialized");
            System.out.println("------------------------");

            SecureRandom sr = new SecureRandom();
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", provider);
            keyGen.initialize(1024, sr);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("privateKey: " + privateKey.toString());

            String plainText = "HELLO WORLD";

            Signature privateSignature = Signature.getInstance("SHA256withRSA", provider);
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes(UTF_8));
            byte[] signature = privateSignature.sign();
            String signatureBase64 = Base64.getEncoder().encodeToString(signature);
            System.out.println(signatureBase64);

            Signature publicSignature = Signature.getInstance("SHA256withRSA", provider);
            publicSignature.initVerify(publicKey);
            publicSignature.update(plainText.getBytes(UTF_8));
            boolean verify = publicSignature.verify(signature);
            System.out.println("verify: " + verify);

//            for (Enumeration<String> aliases = ks.aliases(); aliases.hasMoreElements();) {
//                String alias = aliases.nextElement();
//                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
//                PublicKey publicKey = cert.getPublicKey();
//                PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password);
//                System.out.println("alias: " + alias);
//                System.out.println("privateKey: " + privateKey);
//                System.out.println("cert subject dn: " + cert.getSubjectX500Principal().toString());
//
//                if (privateKey != null) {
//                    String plainText = "HELLO WORLD";
//
//                    Signature privateSignature = Signature.getInstance("SHA256withRSA", provider);
//                    privateSignature.initSign(privateKey);
//                    privateSignature.update(plainText.getBytes(UTF_8));
//                    byte[] signature = privateSignature.sign();
//                    String signatureBase64 = Base64.getEncoder().encodeToString(signature);
//                    System.out.println(signatureBase64);
//
//                    Signature publicSignature = Signature.getInstance("SHA256withRSA", provider);
//                    publicSignature.initVerify(publicKey);
//                    publicSignature.update(plainText.getBytes(UTF_8));
//                    boolean verify = publicSignature.verify(signature);
//                    System.out.println("verify: " + verify);
//                }
//
//               System.out.println("------------------------------");
            }
        }
//    }
/*
public void testPKCS1viaPKCS11() throws Exception {
	File tmpConfigFile = File.createTempFile("pkcs11-", "conf");
	tmpConfigFile.deleteOnExit();
	PrintWriter configWriter = new PrintWriter(new FileOutputStream(tmpConfigFile), true);
	configWriter.println("name=SmartCard");
	configWriter.println("library=/usr/lib/libbeidpkcs11.so.0");
	configWriter.println("slotListIndex=2");

	SunPKCS11 provider = new SunPKCS11(tmpConfigFile.getAbsolutePath());
	Security.addProvider(provider);
	KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
	keyStore.load(null, null);
	PrivateKeyEntry privateKeyEntry = (PrivateKeyEntry) keyStore.getEntry("Authentication", null);
	PrivateKey privateKey = privateKeyEntry.getPrivateKey();
	Signature signature = Signature.getInstance("SHA1withRSA");
	signature.initSign(privateKey);
	byte[] toBeSigned = "hello world".getBytes();
	signature.update(toBeSigned);
	byte[] signatureValue = signature.sign();

	X509Certificate certificate = (X509Certificate) privateKeyEntry.getCertificate();
	RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
	BigInteger signatureValueBigInteger = new BigInteger(signatureValue);
	BigInteger messageBigInteger = signatureValueBigInteger.modPow(publicKey.getPublicExponent(),
			publicKey.getModulus());
	LOG.debug("original message: " + new String(Hex.encodeHex(messageBigInteger.toByteArray())));

	// LOG.debug("ASN.1 signature: " + ASN1Dump.dumpAsString(obj)
}

 */