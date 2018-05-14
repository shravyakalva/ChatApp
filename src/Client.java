/**
 * Created by Divya on 3/1/2018.
 */
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xpath.internal.operations.Bool;
import sun.rmi.runtime.Log;
import sun.security.x509.X500Name;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.security.cert.*;
import javax.security.cert.Certificate;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Array;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Client
{
    private static byte[] ourPbk;
    private static byte[] ourPvk;

    private static byte[] newSecretKey;
    private static byte[] clientSecretKey;
    private static KeyStore ks;
    static String ServerCertificate;


    // Function to encrypt data
    public static String encrypt(String sendMessage ) throws Exception {
        byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
        //SecureRandom secureRandom = new SecureRandom();
        int keyBitSize = 128;
        keyGenerator.init(keyBitSize, secureRandom);
        SecretKey secretKey = new SecretKeySpec(newSecretKey , "AES");

        byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        //   byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        // IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        byte[] plainText  = sendMessage.getBytes("UTF-8");
        // byte[] newByteArray = PadToMultipleOf(plainText,0);
        byte[] cipherText = cipher.doFinal(plainText);
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + iv.length + cipherText.length);
        byteBuffer.putInt(iv.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        byte[] cipherMessage = byteBuffer.array();

        String encryptedText = Base64.encode(cipherMessage);

        //String encryptedText = Base64.encode(cipherText);

        return encryptedText;
    }

    private static void setUpKeyStore() throws Exception {

        ks = KeyStore.getInstance(KeyStore.getDefaultType());
        // get user password and file input stream
        String password = "123s456";

        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream("chatapp.ks");
            ks.load(fis, password.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }

    // function to decrypt data
    private static String decrypt( byte[] cipherText, byte[] iv) throws Exception{
        Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding");
        //  System.out.println("Initialize cipher...");

        byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        // byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        //  IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKey secretKey = new SecretKeySpec(clientSecretKey, "AES");
        cipherD.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        //   System.out.println("Decrypt the single final block...");

        byte[] stringBytes = cipherD.doFinal(cipherText);
        String str = new String(stringBytes, "UTF-8");

        return str;
    }

    private static void conversation(Socket sock) throws Exception {

        // reading from keyboard (keyRead object)
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        // sending to client (pwrite object)
        OutputStream ostream = sock.getOutputStream();
        PrintWriter pwrite = new PrintWriter(ostream, true);

        // receiving from server ( receiveRead  object)
        InputStream istream = sock.getInputStream();
        BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

        System.out.println("Start the chitchat, type and press Enter key");

        String receiveMessage, sendMessage;
        while(true)
        {
            sendMessage = keyRead.readLine();  // keyboard reading

            String str = encrypt(sendMessage);
            pwrite.println(str);       // sending to server
            pwrite.flush();                    // flush the data
            if((receiveMessage = receiveRead.readLine()) != null) //receive from server
            {
                byte[] cipherMessage = Base64.decode(receiveMessage);
                ByteBuffer byteBuffer = ByteBuffer.wrap(cipherMessage);
                int ivLength = byteBuffer.getInt();
                byte[] iv = new byte[ivLength];
                byteBuffer.get(iv);
                byte[] cipherText = new byte[byteBuffer.remaining()];
                byteBuffer.get(cipherText);
                String plaintext = decrypt(cipherText, iv);
                System.out.println(plaintext);
            }
        }
    }

    private static Boolean establishConnection(Socket sock) throws Exception {

        int sequence = 1;

        boolean connectionestablished = false;
        while(!connectionestablished) {

            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            // receiving from server ( receiveRead  object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

            String receiveMessage;
            setUpKeyStore();

            // client send :ka message to server
            if (sequence == 1) {

                String str = ":ka ecdh-secp256r1+x509+aes128/gcm128,ecdh-secp224r1+x509+aes128/gcm128";
                pwrite.println(str);       // sending to server
                pwrite.flush();                    // flush the data
                sequence++;
            }

            //: Client checks for :kaok message and :ka1 message next generates a public/private key and encodes
            // its public key with base64 and sends to server
            if (sequence == 2) {

                if((receiveMessage = receiveRead.readLine()) != null) {

                    String str = getCommand(receiveMessage);
                    if (str.equals(":kaok")) {
                        // System.out.println(receiveMessage);
                        if((receiveMessage = receiveRead.readLine()) != null) {
                            str = getCommand(receiveMessage);
                            if (str.equals(":cert")) {

                                String[] splited = receiveMessage.split("\\s+");
                                String serverCertificate = splited[1];

                                java.security.cert.Certificate serverCert = ks.getCertificate("client");
                                String base64encodedCert = Base64.encode(serverCert.getEncoded());
                                str = ":cert " + base64encodedCert;
                                pwrite.println(str);
                                pwrite.flush();

                                if((receiveMessage = receiveRead.readLine()) != null) {
                                  String command = getCommand(receiveMessage);
                                    if (command.equals(":ka1")) {
                                        keyGeneration();
                                        String publicKey = ourPbk.toString();
                                        Key key = ks.getKey("client", "123s456".toCharArray());
                                        PrivateKey privatekey = (PrivateKey) key;

                                        // Sign public key with privtae key
                                        Signature ec = Signature.getInstance("SHA1withDSA");
                                        ec.initSign((PrivateKey) privatekey);
                                        ec.update(publicKey.getBytes());

                                        String base64encodedString = Base64.encode(ourPbk);
                                        String base64Signature = Base64.encode(publicKey.getBytes("UTF-8"));
                                        str = ":ka1 " + base64encodedString + " " + base64Signature;
                                        pwrite.println(str);
                                        pwrite.flush();

                                        String err = verifyCertificate(serverCertificate,"server");
                                        if (err != null){
                                            str = ":fail " + err;
                                            pwrite.println(str);
                                            pwrite.flush();
                                            return false;
                                        }
                                    }
                                    sequence++;
                                }
                            }
                            else {
                                String error = ":err";
                                pwrite.println(error);       // sending to server
                                pwrite.flush();                    // flush the data
                            }
                        }
                    } else {
                        String error = ":err";
                        pwrite.println(error);       // sending to server
                        pwrite.flush();                    // flush the data
                    }
                }
            }

            // Client recieves sers's public key and generates its own secret key and sends t server
            if (sequence == 3) {
                if((receiveMessage = receiveRead.readLine()) != null) {
                    String command = getCommand(receiveMessage);
                        //    System.out.println(receiveMessage);
                        newSecretKey = receiveMessage.getBytes("UTF-8");
                        System.out.println("Server secret key: " + newSecretKey);
                        String str = new String(computeSharedKey(receiveMessage), "UTF-8");
                        clientSecretKey = str.getBytes("UTF-8");
                        System.out.println("Client key: " + clientSecretKey);
                        pwrite.println(str);
                        pwrite.flush();
                        connectionestablished = true;

                }
                sequence++;
            }

        }
        return connectionestablished;
    }

    public static byte[] computeSharedKey(String publicKey) throws Exception {
        String secret = ourPvk + publicKey;
        byte[] secretKey  = secret.getBytes("UTF-8");
        int endOfArray = secretKey.length - 1;
        byte[] newSecretKey = Arrays.copyOfRange(secretKey,endOfArray - 16 , endOfArray);
        return newSecretKey;
    }


    private static void keyGeneration() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        //kpg.initialize(256);

        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        ourPbk = kp.getPublic().getEncoded();
        ourPvk = kp.getPrivate().getEncoded();
    }

    private static String getCommand(String receiveMessage) {
        String[] commandArray = receiveMessage.split(" ");
        String command = commandArray[0];
        return command;
    }

    private static String verifyCertificate(String cert, String partyName) throws Exception{
        //, Signature signature,String keyExchangeData ,
        String errorMessage = null;

        byte[] encodedCert = Base64.decode(cert);

        java.security.cert.Certificate certificateAuth = ks.getCertificate("cakey");
        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        InputStream in = new ByteArrayInputStream(encodedCert);

        java.security.cert.Certificate userCert = certFactory.generateCertificate(in);
        javax.security.cert.X509Certificate c = convert((java.security.cert.X509Certificate) userCert);

        // check for valid date

        Principal subjectDN = c.getSubjectDN();

        Map<String, String> myMap = new HashMap<String, String>();
        String[] pairs = subjectDN.getName().split(", ");
        for (int i=0;i<pairs.length;i++) {
            String pair = pairs[i];
            String[] keyValue = pair.split("=");
            myMap.put(keyValue[0], keyValue[1]);
        }

        if ( !(myMap.get("CN").equals(partyName))){
           errorMessage = "Invalide User";
        }

        try{
            (c).checkValidity();
        }catch(javax.security.cert.CertificateExpiredException cee) {
            errorMessage = "Certificate is active for current date";
        };


        if (errorMessage != null) { return errorMessage; }
        return null;
    }

    public static javax.security.cert.X509Certificate convert(java.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return javax.security.cert.X509Certificate.getInstance(encoded);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateException e) {
        }
        return null;
    }

    public static void main(String[] args) throws Exception
    {
        Socket sock = new Socket("localhost", 6666);
        while(!establishConnection(sock));
        while(true){
            conversation(sock);
        }
    }


}