/*
 * Copyright 2020 ConsenSys AG.
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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Module;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Sign;
import tech.pegasys.ethsigner.core.signing.Signature;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class HSMCryptoProvider {

  private static final Logger LOG = LogManager.getLogger();
  private static final String CURVE = "secp256k1";

  private Module module;

  private final String library;
  private final Map<Long, Slot> slots;
  private final Map<Long, Session> sessions;
  private final X9ECParameters params;
  private final ECDomainParameters curve;

  public HSMCryptoProvider(final String library) {
    this.library = library;
    this.slots = new HashMap<>();
    this.sessions = new HashMap<>();
    this.params = SECNamedCurves.getByName(CURVE);
    this.curve = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
  }

  public void initialize() {
    try {
      module = Module.getInstance(library);
      module.initialize(null);

      Slot[] slotList = module.getSlotList(true);
      for (Slot s : slotList) {
        LOG.info(s.getSlotID());
        slots.put(s.getSlotID(), s);
      }
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  public void shutdown() {
    try
    {
      for (long slotIndex : slots.keySet()) {
        logout(slotIndex);
      }
      module.finalize(null);
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  public void login(long slotIndex, String slotPin) {
    try {
      Session session = slots.get(slotIndex).getToken().openSession(true, true, null, null);
      session.login(Session.UserType.USER, slotPin.toCharArray());
      sessions.put(slotIndex, session);
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  public void logout(long slotIndex) {
    try {
      sessions.get(slotIndex).logout();
      sessions.get(slotIndex).closeSession();
    } catch (Exception ex) {
      LOG.error(ex);
    }
  }

  public Session openSession(long slotIndex) {
    try {
      return slots.get(slotIndex).getToken().openSession(true, true, null, null);
    } catch (Exception ex) {
      LOG.error(ex);
    }
    return null;
  }

  public Signature sign(long slotIndex, byte[] hash, String address) {
    Session session = openSession(slotIndex);

    ECPrivateKey privateKeyHandle = getPrivateKeyHandle(session, address);
    ECPublicKey publicKeyHandle = getPublicKeyHandle(session, address);
    byte[] publicKeyBytes = getPublicKey(publicKeyHandle);
    final BigInteger publicKey = Sign.publicFromPoint(publicKeyBytes);

    byte[] signature;
    try {
      session.signInit(Mechanism.get(PKCS11Constants.CKM_ECDSA), privateKeyHandle);
      signature = session.sign(hash);

    } catch (Exception ex) {
      LOG.error(ex);
      throw new RuntimeException("Failed to produce a valid signature for the hash.");
    }
    finally {
      try {
        session.closeSession();
      } catch (Exception ex) {
        LOG.error(ex);
      }
    }
    ECDSASignature canonicalSignature = null;
    try {
      canonicalSignature = transposeSignatureToLowS(signature);
    } catch (Exception ex) {
      LOG.error(ex);
      throw new RuntimeException("Failed to transpose signature.");
    }

    // Now we have to work backwards to figure out the recId needed to recover the signature.
    final int recId = recoverKeyIndex(canonicalSignature, hash, publicKey);
    if (recId == -1) {
      throw new RuntimeException("Failed to construct a recoverable key. Are your credentials valid?");
    }

    final int headerByte = recId + 27;
    return new Signature(BigInteger.valueOf(headerByte), canonicalSignature.r, canonicalSignature.s);
  }

  // transposeSignatureToLowS ensures that the signature has a low S value as Ethereum requires.
  private ECDSASignature transposeSignatureToLowS(byte[] signature) throws Exception {
    byte[] r = Arrays.copyOfRange(signature, 0, signature.length/2);
    BigInteger R = new BigInteger(1, r);
    byte[] s = Arrays.copyOfRange(signature, signature.length/2, signature.length);
    BigInteger S = new BigInteger(1, s);
    final ECDSASignature initialSignature = new ECDSASignature(R, S);
    final ECDSASignature canonicalSignature = initialSignature.toCanonicalised();
    return canonicalSignature;
  }

  // getECPoint returns the CKA_EC_POINT of the given public key.
  private byte[] getECPoint(ECPublicKey publicKey) {
    return publicKey.getEcPoint().getByteArrayValue();
  }

  // getDecodedECPoint decodes the CKA_EC_POINT and removes the DER encoding.
  private byte[] getDecodedECPoint(ECPublicKey publicKey)  {

    try {
      byte[] encodedPoint = DEROctetString.getInstance(getECPoint(publicKey)).getOctets();
      return curve.getCurve().decodePoint(encodedPoint).getEncoded(false);
    } catch (Exception ex) {
      LOG.error(ex);
    }
    return null;
  }

  private byte[] getPublicKey(ECPublicKey publicKey) {
    byte[] ecPoint = getDecodedECPoint(publicKey);
    return ecPoint;
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

  private PKCS11Object findObject(Session session, Key key) {
    PKCS11Object[] objects;
    try {
      session.findObjectsInit(key);
      objects = session.findObjects(1);
      session.findObjectsFinal();
      if (objects.length > 0) {
        return objects[0];
      }
    }
    catch (TokenException ex) { LOG.error(ex); }
    return null;
  }

  private ECPrivateKey getPrivateKeyHandle(Session session, String address) {
    PrivateKey key = new PrivateKey();
    key.getLabel().setCharArrayValue(address.toCharArray());
    return (ECPrivateKey) findObject(session, key);
  }

  private ECPublicKey getPublicKeyHandle(Session session, String address) {
    PublicKey key = new PublicKey();
    key.getLabel().setCharArrayValue(address.toCharArray());
    return (ECPublicKey) findObject(session, key);
  }

  public List<PrivateKey> getAll(long slotIndex) {
    Session session = openSession(slotIndex);
    PrivateKey key = new PrivateKey();
    List<PrivateKey> result = new ArrayList<>();
    try {
      session.findObjectsInit(key);
      PKCS11Object[] objects = session.findObjects(100);
      session.findObjectsFinal();

      for (PKCS11Object object : objects) {
        LOG.info(object.getAttribute(PKCS11Constants.CKA_LABEL));
        result.add((PrivateKey)object);
      }
    } catch (Exception ex) {
      LOG.error(ex);
    } finally {
      try {
        session.closeSession();
      }
      catch (TokenException ex)
      {
        LOG.error(ex);
      }
    }
    return result;
  }
}
