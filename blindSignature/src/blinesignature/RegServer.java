/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package blinesignature;

/**
 *
 * @author Yifei
 */
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Map;

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
import org.bouncycastle.util.encoders.Base64;

public class RegServer {

    private final AsymmetricCipherKeyPair keys;
    private Map<String, ArrayList<String>> list;
    private ArrayList<String> votingList;

    public RegServer(AsymmetricCipherKeyPair keys, Map<String, ArrayList<String>> list) {
        this.list = list;
        this.keys = keys;
    }

    /*
     1. rs decrypt message using its private key
     2. rs look up voting list using voting id
     3. rs look up voter id in voting list
     4. rs sign the blinded message
     */
    public byte[] authenticate(AsymmetricKeyParameter publicKey, ArrayList<byte[]> infoList) throws Exception {
        byte[] signedVoterId = decrypt(infoList.get(0));
        byte[] signedBli1 = decrypt(infoList.get(1));
        byte[] signedVotingId = decrypt(infoList.get(2));

        System.out.println();
        System.out.println("5. (rs) Decrypt the message");
        System.out.println("****************************");
        System.out.println("**** Decrypt succeeded *****");
        System.out.println("****************************");

        String voterId = getHexString(verify(signedVoterId, publicKey));
        byte[] bli1 = verify(signedBli1, publicKey);
        String votingId = getHexString(verify(signedVotingId, publicKey));

        boolean hasVoter = false;
        if (list.containsKey(votingId)) {
            votingList = list.get(votingId);

            System.out.println();
            System.out.println("6. (rs) Get the voting list by voting id");
            System.out.println("****************************");
            System.out.println("**** Return voting list ****");
            System.out.println("****************************");

            for (String temp : votingList) {
                if (temp.equals(voterId)) {
                    System.out.println();
                    System.out.println("7. (rs) Check whether voter id is in voting list");
                    System.out.println("****************************");
                    System.out.println("** Voter id is in the list *");
                    System.out.println("****************************");

                    hasVoter = true;
                    byte[] feedback = sign(bli1);

                    System.out.println();
                    System.out.println("8. (rs) Sign the blinded message:(below is the signed message)");
                    System.out.println(getHexString(feedback));
                    
                    return feedback;
                }
            }
        }
        if (!hasVoter) {
            System.out.println();
            System.out.println("****************************");
            System.out.println("********* Warning **********");
            System.out.println("****************************");
            System.out.println("The voter is not in the list");
            return null;
        }

        return null;
    }

    public byte[] encrypt(byte[] inputData, AsymmetricKeyParameter publicKey) {

        RSAEngine engine = new RSAEngine();
        engine.init(true, publicKey);
        return engine.processBlock(inputData, 0, inputData.length);
    }

    public RSAKeyParameters getPublic() {
        return (RSAKeyParameters) keys.getPublic();
    }

    /*
     decrypt
     */
    private byte[] decrypt(byte[] signature) {
        RSAEngine engine = new RSAEngine();
        engine.init(false, keys.getPrivate());
        return engine.processBlock(signature, 0, signature.length);
    }

    /*
     verify message
     */
    public byte[] verify(byte[] signature, AsymmetricKeyParameter publicKey) {
        RSAEngine engine = new RSAEngine();
        engine.init(false, publicKey);
        return engine.processBlock(signature, 0, signature.length);
    }

    public static String getHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result
                    += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    /*
     Sign message
     */
    private byte[] sign(byte[] signature) {
        //System.out.println(signature.length);
        RSAEngine engine = new RSAEngine();
        engine.init(true, keys.getPrivate());
        return engine.processBlock(signature, 0, signature.length);
    }
}
