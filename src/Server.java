import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import sun.security.x509.CertAttrSet;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.cert.Certificate;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Server
{
    private static byte[] ourPbk;
    private static byte[] ourPvk;
    private static byte[] newSecretKey;
    private static byte[] serverSecretkey;
    private static KeyStore ks;

    public static String encrypt(String sendMessage ) throws Exception {
        byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
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


    private static void converation(Socket sock) throws Exception {

        // reading from keyboard (keyRead object)
        BufferedReader keyRead = new BufferedReader(new InputStreamReader(System.in));
        // sending to client (pwrite object)
        OutputStream ostream = sock.getOutputStream();
        PrintWriter pwrite = new PrintWriter(ostream, true);

        // receiving from server ( receiveRead  object)
        InputStream istream = sock.getInputStream();
        BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

        String receiveMessage, sendMessage;
        while(true)
        {
            if((receiveMessage = receiveRead.readLine()) != null)
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
            sendMessage = keyRead.readLine();

            String str = encrypt(sendMessage);

            pwrite.println(str);
            pwrite.flush();
        }
    }

    private static String decrypt( byte[] cipherText, byte[] iv) throws Exception{
        Cipher cipherD = Cipher.getInstance("AES/GCM/NoPadding");
        //  System.out.println("Initialize cipher...");

        byte[] keyBytes = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        // byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        //  IvParameterSpec ivspec = new IvParameterSpec(iv);

        SecretKey secretKey = new SecretKeySpec(serverSecretkey, "AES");
        cipherD.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));
        //   System.out.println("Decrypt the single final block...");

        byte[] stringBytes = cipherD.doFinal(cipherText);
        String str = new String(stringBytes, "UTF-8");

        return str;

    }



    private static boolean establishConnection(Socket sock) throws Exception {

        int sequence = 1;
        boolean connectionestablished = false;

        while(!connectionestablished) {

            // receiving from server ( receiveRead  object)
            InputStream istream = sock.getInputStream();
            BufferedReader receiveRead = new BufferedReader(new InputStreamReader(istream));

            OutputStream ostream = sock.getOutputStream();
            PrintWriter pwrite = new PrintWriter(ostream, true);

            String receiveMessage;
            setUpKeyStore();
            // Server recieves the :ka message from client and responds with :ka1 message
            if (sequence == 1) {
                if((receiveMessage = receiveRead.readLine()) != null)
                {
                    String command = getCommand(receiveMessage);
                    if (command.equals(":ka"))
                    {
                        String str = ":kaok ecdh-secp224r1+x509+aes128/gcm128";
                        pwrite.println(str);
                        pwrite.flush();

                        java.security.cert.Certificate serverCert = ks.getCertificate("servercert");
                        String base64encodedCert = Base64.encode(serverCert.getEncoded());
                        str = ":cert " + base64encodedCert;
                        pwrite.println(str);
                        pwrite.flush();
                        //sequence++;

                        if((receiveMessage = receiveRead.readLine()) != null) {
                            command = getCommand(receiveMessage);
                            if (command.equals(":cert")){

                                String[] splited = receiveMessage.split("\\s+");
                                String ClientCertificate = splited[1];

                                keyGeneration();
                                String publicKey = ourPbk.toString();

                                Key key = ks.getKey("server", "123s456".toCharArray());
                                PrivateKey privatekey = (PrivateKey) key;

                                // Sign public key with privtae key
                                Signature ec = Signature.getInstance("SHA1withDSA");
                                ec.initSign(privatekey);
                                ec.update(publicKey.getBytes());

                                String base64encodedString = Base64.encode(ourPbk);
                                String base64Signature = Base64.encode(publicKey.getBytes("UTF-8"));
                                //  System.out.println(ourPbk);
                                str = ":ka1 " + base64encodedString + " " + base64Signature;
                                pwrite.println(str);
                                pwrite.flush();

                                String err = verifyCertificate(ClientCertificate,"client");
                                if (err != null) {
                                    str = ":fail " + err;
                                    pwrite.println(str);
                                    pwrite.flush();
                                    return false;
                                }
                            }
                        }
                    }
                }
                sequence++;
            }

            // server recieves clients public key and combines it with its private key and generates a secret key
            if (sequence == 2) {
                if((receiveMessage = receiveRead.readLine()) != null){
                    String command = getCommand(receiveMessage);
                    if (command.equals(":ka1")){
                        String[] splited = receiveMessage.split("\\s+");
                        String keyExchangeData = splited[1];

                        String str = new String(computeSharedKey(keyExchangeData), "UTF-8");
                        serverSecretkey = str.getBytes("UTF-8");
                        System.out.println("Server Key: " + serverSecretkey);
                        pwrite.println(str);
                        pwrite.flush();
                    }
                }

                //else {sersock.close();}
                sequence++;
            }

            // server recieves clients secret key
            if (sequence == 3) {
                if((receiveMessage = receiveRead.readLine()) != null)
                {
                    //    System.out.println(receiveMessage);
                    newSecretKey = receiveMessage.getBytes("UTF-8");
                       System.out.println("Client Key: " + newSecretKey);
                    connectionestablished = true;
                    //return receiveMessage;
                }
                sequence++;

            }
        }
        return connectionestablished;
    }

    private static String verifyCertificate(String cert, String partyName) throws Exception{

        String errorMessage = null;
        // ,String cert, Signature signature,String keyExchangeData
        byte[] encodedCert = Base64.decode(cert);

        CertificateFactory certFactory = CertificateFactory.getInstance("X509");
        InputStream in = new ByteArrayInputStream(encodedCert);

        java.security.cert.Certificate userCert = certFactory.generateCertificate(in);
        X509Certificate c = convert((java.security.cert.X509Certificate) userCert);
        Principal subjectDN = c.getSubjectDN();

        Map<String, String> myMap = new HashMap<String, String>();
        String[] pairs = subjectDN.getName().split(", ");
        for (int i=0;i<pairs.length;i++) {
            String pair = pairs[i];
            String[] keyValue = pair.split("=");
            myMap.put(keyValue[0], keyValue[1]);
        }
        System.out.println(partyName);
        if ( !(myMap.get("CN").equals(partyName))){
            errorMessage = "Invalide User";
        }
        // check for valid date
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

    private static String getCommand(String receiveMessage) {
        String[] commandArray = receiveMessage.split(" ");
        String command = commandArray[0];
        return command;
    }

    private static void keyGeneration() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

        ECGenParameterSpec ecsp;
        ecsp = new ECGenParameterSpec("secp256r1");
        kpg.initialize(ecsp);

        KeyPair kp = kpg.genKeyPair();
        ourPbk = kp.getPublic().getEncoded();
        ourPvk = kp.getPrivate().getEncoded();

    }

    public static byte[] computeSharedKey(String publicKey) throws Exception {
        String secret = ourPvk + publicKey;
        byte[] secretKey  = secret.getBytes("UTF-8");
        int endOfArray = secretKey.length - 1;
        byte[] newSecretKey = Arrays.copyOfRange(secretKey,endOfArray - 16 , endOfArray);
        return newSecretKey;
    }

    public static void main(String[] args) throws Exception
    {
        ServerSocket sersock = new ServerSocket(6666);
        System.out.println("Server  ready for chatting");
        Socket sock = sersock.accept( );

        while(!establishConnection(sock));
        while(true) {
            converation(sock);
        }
    }
}                        