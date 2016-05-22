/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package blinesignature;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;
import sun.applet.resources.MsgAppletViewer;
import sun.misc.BASE64Decoder;

/**
 *
 * @author Yifei
 */
public class Voter {

    private String id;
    private byte[] blindedMessage;
    private final byte[] message;
    private final AsymmetricCipherKeyPair keys;
    private RSABlindingParameters blindingParams;

    public Voter(String id, AsymmetricCipherKeyPair keys, byte[] message) {
        this.message = message;
        this.keys = keys;
        this.id = id;
        blindingParams = null;
    }

    public byte[] getMessage() {
        return message;
    }

    public RSAKeyParameters getPublic() {
        return (RSAKeyParameters) keys.getPublic();
    }
    /*
     Blind message
     */

    public byte[] blind(AsymmetricKeyParameter publicKey) throws CryptoException {

        RSAKeyParameters pub = (RSAKeyParameters) publicKey;
        RSABlindingFactorGenerator blindingFactorGenerator
                = new RSABlindingFactorGenerator();
        blindingFactorGenerator.init(pub);

        BigInteger blindingFactor
                = blindingFactorGenerator.generateBlindingFactor();
        blindingParams = new RSABlindingParameters(pub, blindingFactor);

        PSSSigner signer = new PSSSigner(new RSABlindingEngine(),
                new SHA1Digest(), 20);
        signer.init(true, blindingParams);

        signer.update(message, 0, message.length);
        RSABlindingEngine eng = new RSABlindingEngine();
        eng.init(true, blindingParams);
        blindedMessage = signer.generateSignature();
        try {
            System.out.println();
            System.out.println("1. (Voter) blind the message:(below is the blinded message)");
            System.out.println(getHexString(blindedMessage));
        } catch (Exception ex) {
            Logger.getLogger(Voter.class.getName()).log(Level.SEVERE, null, ex);
        }
        return blindedMessage;
    }

    /*
     Generate request for authentication
     */
    public ArrayList<byte[]> requestAuth(String votingId, AsymmetricKeyParameter publicKey) {
        try {
            // put voting id, bli1, voter id into a map, and convert map to byte array
            byte[] voterId = hexStringToByteArray(id);
            byte[] signedVoterId = sign(voterId);
            byte[] signedBli1 = sign(blindedMessage);
            byte[] signedVotingId = sign(hexStringToByteArray(votingId));
            System.out.println();
            System.out.println("2. (Voter) Sign the message");
            System.out.println("****************************");
            System.out.println("****** Sign succeeded ******");
            System.out.println("****************************");
//            Map<String, String> data = new HashMap<String, String>();

//            data.put("VotingId", votingId);
//            data.put("bli1", bli1);
//            data.put("voterId", ""+id);
//            ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
//            ObjectOutputStream out = new ObjectOutputStream(byteOut);
//            out.writeObject(data);
//            byte[] dataToSign = byteOut.toByteArray();
            // sign the data
//            byte[] dataSigned = sign(dataToSign);
            // put data and public key into 
//            Map<String, byte[]> dataToEncrypt = new HashMap<String, byte[]>();
//            dataToEncrypt.put("VoterId", signedVoterId);
//            dataToEncrypt.put("BlindMessage", signedBli1);
//            dataToEncrypt.put("VotingId", signedVotingId);
//            
//            out.writeObject(dataToEncrypt);
//            byte[] cipherText = encrypt(byteOut.toByteArray());
            ArrayList<byte[]> list = new ArrayList<byte[]>();
            encrypt(signedVoterId, publicKey);
            list.add(encrypt(signedVoterId, publicKey));
            list.add(encrypt(signedBli1, publicKey));
            list.add(encrypt(signedVotingId, publicKey));

            System.out.println();
            System.out.println("3. (Voter) Encrypt the message");
            System.out.println("****************************");
            System.out.println("*** Encryption succeeded ***");
            System.out.println("****************************");
            return list;
        } catch (Exception ex) {
            Logger.getLogger(Voter.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }


    /*
     Sign message
     */
    public byte[] sign(byte[] signature) {
        //System.out.println(signature.length);
        RSAEngine engine = new RSAEngine();
        engine.init(true, keys.getPrivate());
        return engine.processBlock(signature, 0, signature.length);
    }

    /*
     verify message
     */
    public byte[] unsign(byte[] signature) {
        RSAEngine engine = new RSAEngine();
        engine.init(false, keys.getPublic());
        return engine.processBlock(signature, 0, signature.length);
    }

    public byte[] unblind(byte[] signature) {
        RSABlindingEngine blindingEngine = new RSABlindingEngine();
        blindingEngine.init(false, blindingParams);
        byte[] s = blindingEngine.processBlock(signature, 0, signature.length);

        
        try {
            System.out.println();
            System.out.println("10. (Voter) unblind the signed message:(below is the signature)");
            System.out.println(getHexString(s));
        } catch (Exception ex) {
            Logger.getLogger(Voter.class.getName()).log(Level.SEVERE, null, ex);
        }
        return s;
    }

    public void verify(byte[] msg, AsymmetricKeyParameter publicKey) throws UnsupportedEncodingException {
//        System.out.println(new String(message, "UTF-8"));

//        msg = decrypt(msg);
        PSSSigner pssVerif = new PSSSigner(new RSAEngine(), new SHA1Digest(), 20);
        pssVerif.init(false, publicKey);
        pssVerif.update(message, 0, message.length);
        boolean b = pssVerif.verifySignature(msg);
        System.out.println();
        System.out.println("This step verify whether the signature is signed by rs.(just for testing) ");
        System.out.print("The result only returns true/false:  ");

        if (b) {
            System.out.println("True");
        }else{
            System.out.println("False");
        }
        System.out.println();
    }

    public byte[] encrypt(byte[] inputData, AsymmetricKeyParameter publicKey) {

        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey);
        return engine.processBlock(inputData, 0, inputData.length);
    }
//    public String encrypt(String inputData) {
//
//        String encryptedData = null;
//        try {
//
//            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//            AsymmetricBlockCipher e = new RSAEngine();
//            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
//            e.init(true, keys.getPublic());
//
//            byte[] messageBytes = inputData.getBytes();
//            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
//
//            System.out.println(getHexString(hexEncodedCipher));
//            encryptedData = getHexString(hexEncodedCipher);
//
//        } catch (Exception e) {
//            System.out.println(e);
//        }
//
//        return encryptedData;
//    }

    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result
                    += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    /*
     decrypt
     */
    private byte[] decrypt(byte[] signature) {
        RSAEngine engine = new RSAEngine();
        engine.init(false, keys.getPrivate());
        return engine.processBlock(signature, 0, signature.length);
    }

//    public String decrypt (String encryptedData) {
//
//        String outputData = null;
//        try {
//
//            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//            AsymmetricBlockCipher e = new RSAEngine();
//            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
//            e.init(false, keys.getPrivate());
//
//            byte[] messageBytes = hexStringToByteArray(encryptedData);
//            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
//
//            System.out.println();
//            System.out.println(new String(hexEncodedCipher));
//            outputData = new String(hexEncodedCipher);
//
//        }
//        catch (Exception e) {
//            System.out.println(e);
//        }
//       
//        return outputData;
//    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}
