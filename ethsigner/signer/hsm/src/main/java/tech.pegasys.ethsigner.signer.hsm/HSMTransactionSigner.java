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

import tech.pegasys.ethsigner.core.signing.Signature;
import tech.pegasys.ethsigner.core.signing.TransactionSigner;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;

public class HSMTransactionSigner implements TransactionSigner {

  private static final Logger LOG = LogManager.getLogger();

  private final HSMKeyStoreProvider provider;
  private final String address;

  public HSMTransactionSigner(final HSMKeyStoreProvider provider, String address) {
    this.provider = provider;
    this.address = address;
  }

  @Override
  public Signature sign(final byte[] data) {

    PrivateKeyEntry privateKeyEntry = null;
    try {
      privateKeyEntry = (PrivateKeyEntry) provider.getKeyStore().getEntry(address, null);
    } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to get private key from key store");
    }
    PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    Certificate certificate = null;
    try {
      certificate = provider.getKeyStore().getCertificate(address);
    } catch (KeyStoreException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to get certificate from key store");
    }
    PublicKey publicKey = certificate.getPublicKey();

    final byte[] hash = Hash.sha3(data);
    java.security.Signature sig = null;
    try {
      sig = java.security.Signature.getInstance("NONEwithECDSA", provider.getProvider());
    } catch (NoSuchAlgorithmException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to get hsm signing service for this algorithm");
    }
    try {
      sig.initSign(privateKey);
    } catch (InvalidKeyException ex) {
      LOG.trace(ex);
      throw new RuntimeException(
          "Failed to initialize hsm signing service with private key handle");
    }
    try {
      sig.update(hash);
    } catch (SignatureException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to initialize hsm signing service with provided hash");
    }
    byte[] signature = new byte[0];
    try {
      signature = sig.sign();
    } catch (SignatureException ex) {
      LOG.trace(ex);
      throw new RuntimeException("Failed to sign provided hash with hsm signing service");
    }
    if (signature.length != 64) {
      throw new RuntimeException(
          "Invalid signature from hsm signing service, must be 64 bytes long");
    }

    // The output of this will be a 64 byte array. The first 32 are the value for R and the rest is
    // S.
    final BigInteger R = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
    final BigInteger S = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

    // The signature MAY be in the "top" of the curve, which is illegal in Ethereum thus it must be
    // transposed to the lower intersection.
    final ECDSASignature initialSignature = new ECDSASignature(R, S);
    final ECDSASignature canonicalSignature = initialSignature.toCanonicalised();
    final ECPoint w = ((ECPublicKey) publicKey).getW();

    // Now we have to work backwards to figure out the recId needed to recover the signature.
    final int recId = recoverKeyIndex(canonicalSignature, hash, w.getAffineX());
    if (recId == -1) {
      throw new RuntimeException(
          "Could not construct a recoverable key. Are your credentials valid?");
    }

    final int headerByte = recId + 27;
    return new Signature(
        BigInteger.valueOf(headerByte), canonicalSignature.r, canonicalSignature.s);
  }

  private int recoverKeyIndex(final ECDSASignature sig, final byte[] hash, BigInteger publicKey) {
    for (int i = 0; i < 4; i++) {
      final BigInteger k = Sign.recoverFromSignature(i, sig, hash);
      if (k != null && k.equals(publicKey)) {
        return i;
      }
    }
    return -1;
  }

  @Override
  public String getAddress() {
    return address;
  }
}
