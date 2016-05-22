/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package blinesignature;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author Yifei
 */
public class BlineSignature {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here

        try {
            // Message for registration
            String message = "";
            Scanner sc = new Scanner(System.in);
            System.out.println("Please Enter Message:");
            message = sc.next();
            byte[] messageByte = message.getBytes("UTF-8");

            final long startTime = System.currentTimeMillis();

            /*
             hardcode for test the registration process
             voting list which contains eligible voter id, VotingID: a1
             */
            ArrayList<String> a1 = new ArrayList<String>();
            a1.add("12");
            a1.add("13");

            /*
             Map cantains voting lists for different voting id
             */
            Map<String, ArrayList<String>> vlist = new HashMap<String, ArrayList<String>>();
            vlist.put("a1", a1);

            /*
             Registration Server rs
             Generate rs' private key and public key
             Assign list of votings to rs
             */
            RegServer rs = new RegServer(generateKeyPair(), vlist);

            /*
             Voter voter
             set id to 12
             Generate voter's private key and public key
             */
            Voter voter = new Voter("12", generateKeyPair(), messageByte);

            /*
             Blind the message
             */
            voter.blind(rs.getPublic());

            /*
             1. Voter signs voting id, voter id, and blinded message by Voter's private key
             2. Voter encrypt signed message by rs's public key
             3. Put all the encrypted message in an array list
             */
            ArrayList<byte[]> list = voter.requestAuth("a1", rs.getPublic());

            System.out.println();
            System.out.println("4. (Voter) Send the encrypted message to rs");

            System.out.println();
            System.out.println();
            System.out.println("*********************************This is a line*******************************");
            System.out.println();
            System.out.println();

            /*
             1. rs decrypt message using its private key
             2. rs look up voting list using voting id
             3. rs look up voter id in voting list
             4. rs sign the blinded message
             */
            byte[] feedback = rs.authenticate(voter.getPublic(), list);

            if (feedback != null) {
                System.out.println();
                System.out.println("9. (rs) Send the signed message to voter");

                /*
                 Voter unblind signature
                 */
                feedback = voter.unblind(feedback);

                System.out.println();
                System.out.println();
                System.out.println("********************************* Verify the Result *******************************");
                System.out.println();

                /*
                 Voter verify signature with rs' pulic key
                 */
                voter.verify(feedback, rs.getPublic());
//                System.out.println(new String(voter.verify(voter.getSignature(feedback),rs.getPublic()), "UTF-8"));

                final long endTime = System.currentTimeMillis();

                System.out.println("Total execution time: " + (endTime - startTime) + " Millisecond");
            }

        } catch (Exception ex) {
            Logger.getLogger(BlineSignature.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public static AsymmetricCipherKeyPair generateKeyPair() {
        // Generate a 2048-bit RSA key pair.
        RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
        generator.init(new RSAKeyGenerationParameters(
                new BigInteger("10001", 16), new SecureRandom(), 2048,
                80));
        return generator.generateKeyPair();
    }
}
