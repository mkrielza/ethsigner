package tech.pegasys.ethsigner.signer.hsm;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedWriter;
import java.io.OutputStreamWriter;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class HSMKeyStoreProvider {

    private static final Logger LOG = LogManager.getLogger();
    private static final String ERROR_CREATING_TMP_FILE_MESSAGE = "";
    private static final String ERROR_ACCESSING_TMP_FILE_MESSAGE = "";
    private static final String ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE = "";
    private static final String ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE = "";

    private KeyStore keyStore = null;

    public HSMKeyStoreProvider(final String library, final String slot, final String pin) {
        File tmpConfigFile = null;
        try {
            tmpConfigFile = File.createTempFile("pkcs11-", "conf");
        } catch (IOException ex) {
            LOG.debug(ERROR_CREATING_TMP_FILE_MESSAGE);
            LOG.trace(ex);
            throw new HSMKeyStoreInitializationException(ERROR_CREATING_TMP_FILE_MESSAGE, ex);
        }
        tmpConfigFile.deleteOnExit();
        PrintWriter configWriter = null;
        try {
            configWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(tmpConfigFile), Charset.defaultCharset())), true);
        } catch (FileNotFoundException ex) {
            LOG.debug(ERROR_ACCESSING_TMP_FILE_MESSAGE);
            LOG.trace(ex);
            throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_TMP_FILE_MESSAGE, ex);
        }
        configWriter.println(String.format("name=%s", "EthSigner"));
        configWriter.println(String.format("library=%s", library));
        configWriter.println(String.format("slot=%s", slot));
        String configName = tmpConfigFile.getAbsolutePath();

        Provider prototype = Security.getProvider("SunPKCS11");
        Provider provider = prototype.configure(configName);

        try {
            keyStore = KeyStore.getInstance("PKCS11", provider);
        } catch (KeyStoreException ex) {
            LOG.debug(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE);
            LOG.trace(ex);
            throw new HSMKeyStoreInitializationException(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE, ex);
        }
        try {
            keyStore.load(null, pin.toCharArray());
        } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
            LOG.debug(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE);
            LOG.trace(ex);
            throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE, ex);
        }
        System.out.println("Successfully initialized slot");
        System.out.println("-----------------------------");
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
