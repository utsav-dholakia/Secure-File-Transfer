import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.util.io.pem.PemReader;
import org.omg.CORBA.Object;


public class Server {

    private Integer serverPortNumber;
    public static ServerSocket serverSocket;
    String localFolderPath = "file-storage/";
    private byte[] sessionKey;
    byte[] integrityKey, encryptionKey, ivValue;
    private Socket clientSocket;
    OutputStream outStream;
    InputStream inStream;
    DataInputStream dis;
    DataOutputStream dos;
    private boolean serverOn;
    MessageDigest digest;
    PrivateKey privateKeyServer;
    PublicKey publicKeyServer;
    X509Certificate serverCertificate;
    ObjectOutputStream objOS;
    ObjectInputStream objIS;

    public static void main(String[] args) throws IOException {

        Server obj = new Server();
        obj.serverPortNumber = 9000;
        obj.serverOn = true;
        /*if(args.length != 0) {
            portNum = Integer.parseInt(args[0]);
        }
        Listener listener = new Listener(portNum);
        Thread listenerThread = new Thread(listener, "Listener Thread");
        listenerThread.start();*/

        try{
            obj.initializeServerCertificate();
            serverSocket = new ServerSocket(obj.serverPortNumber);
            while(obj.serverOn) {
                //Initialize the receiver as a continuous listening server
                System.out.println("Listening on port : " + obj.serverPortNumber);
                obj.clientSocket = serverSocket.accept();
                System.out.println("Client connected");
                String command;
                while(true){
                    command = obj.readCommand();
                    if(command.equalsIgnoreCase("Exit")){
                        System.out.println("Client: Close connection");
                        obj.closeCommunication();
                        break;
                    }
                }
            }
        } catch(Exception e){
            e.printStackTrace();
            obj.closeCommunication();
        }


    }

    private void initializeServerCertificate(){
        try {
            File spub = new File("Server-certs/server-public.pem");
            String priv = "Server-certs/private";
            //Extract public and private keys of server
            privateKeyServer = getPrivateKey(priv);
            //System.out.println(pvS);
            publicKeyServer = get(spub);

            //Verifying Server CA
            File serverCert = new File("Server-certs/mycert.pem");
            //Generate X509 format certificate from CA issued certificate for server and send it to client
            serverCertificate = getX509(serverCert);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static byte[] encrypt(PublicKey key, byte[] plaintext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(PrivateKey key, byte[] ciphertext) throws Exception
    {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
    }

    public static X509Certificate getX509(File serverCert) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream (serverCert);
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        return cer;
    }


    public static PublicKey get(File publicKeyFile) throws Exception {
        FileReader file = new FileReader(publicKeyFile);
        PemReader reader = new PemReader(file);
        X509EncodedKeySpec caKeySpec = new X509EncodedKeySpec(reader.readPemObject().getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey caKey = kf.generatePublic(caKeySpec);
        return caKey;
    }

    public static PrivateKey getPrivateKey(String filename) throws Exception {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private void authenticateWithClient() throws IOException {
        objOS.writeObject(serverCertificate);
        objOS.flush();
    }

    private void generateKeys() throws NoSuchAlgorithmException{
        digest = MessageDigest.getInstance("SHA-1");
        //Generate encryption and integrity keys from session key
        encryptionKey = new byte[16];
        integrityKey = new byte[16];
        ivValue = new byte[8];
        for(int i = 0; i < sessionKey.length; i++){
            encryptionKey[i] = (byte)(sessionKey[i] + 1);
            integrityKey[i] = (byte)(sessionKey[i] - 1);
            if(i < 8){
                ivValue[i] = (byte)(sessionKey[i] << 1);
            }
        }
    }

    private void closeCommunication() throws IOException {
        clientSocket.close();
        sessionKey = null;
    }

    private void writeCommand(String message) throws NoSuchAlgorithmException, IOException {
        outStream = clientSocket.getOutputStream();
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] encodedHash = digest.digest(message.getBytes(StandardCharsets.UTF_8));
        outStream.write(encodedHash);
        outStream.flush();
        System.out.println("Server: " + message);
        outStream.close();
    }

    private String readCommand() throws Exception {
        if(inStream == null){
            inStream = clientSocket.getInputStream();
        }
        if(outStream == null){
            outStream = clientSocket.getOutputStream();
        }
        if(dis == null){
            dis = new DataInputStream(inStream);
        }
        if(dos == null){
            dos = new DataOutputStream(outStream);
        }
        if(objOS == null) {
            objOS = new ObjectOutputStream(outStream);
        }
        if(objIS == null){
            objIS = new ObjectInputStream(inStream);
        }
        String command = objIS.readUTF();
        if(command.equalsIgnoreCase("Sync")){
            authenticateWithClient();
        }
        else if(command.equalsIgnoreCase("Key")){
            if(sessionKey == null){
                sessionKey = new byte[16];
                int readKeyLength = objIS.readInt();
                byte[] tempKey = new byte[readKeyLength];
                objIS.read(tempKey);
                byte[] decryptedKey = decrypt(privateKeyServer, tempKey);
                sessionKey = Arrays.copyOf(decryptedKey, 16);
                generateKeys();
            }
            else{
                //Ignore Key command, as key is already established, this may be replay attack for setting key again
            }

        }
        else if(command.equalsIgnoreCase("Upload")){
            String fileName = objIS.readUTF();
            decryptAndStoreFile(objIS, fileName);
        }
        else if(command.equalsIgnoreCase("Download")){
            File file;
            while(true){
                String fileName = objIS.readUTF();
                file = new File(localFolderPath + fileName);
                if(file.exists()){
                    objOS.writeUTF("Found");
                    objOS.flush();
                    break;
                }
                else{
                    objOS.writeUTF("Not Found");
                    objOS.flush();
                }
            }
            encryptAndSendFile(objOS, file);
        }
        return command;
    }

    private void decryptAndStoreFile(ObjectInputStream objIS, String fileName) throws IOException{
        long bytesToRead = objIS.readLong();
        File file = new File(localFolderPath + fileName);
        FileOutputStream fos = new FileOutputStream(file);
        boolean firstBlock = true;
        long bytesReadTillNow = 0;
        byte[] ci = new byte[9];
        byte[] bi = new byte[8];
        byte[] pi = new byte[8];
        byte[] ti = new byte[8];
        while(bytesToRead > 0 && bytesReadTillNow < bytesToRead){
            objIS.read(ci);
            bytesReadTillNow += 8;
            if(firstBlock){
                bi = gnrtIntrBlks(ivValue);
            }
            else{
                bi = gnrtIntrBlks(ci);
            }
            for(int i = 0; i < 8; i++){
                ti[i] = ci[i];
                pi[i] = (byte)(ci[i] ^ bi[i]);
            }
            if(getHash(ti)!= ci[8]){
                System.out.println("Error");
            }
            fos.write(pi);
        }
        fos.flush();
        fos.close();
    }

    private void encryptAndSendFile(ObjectOutputStream objOS, File file) throws IOException {
        //The encrypted block size is 8-bytes, ci = pi XOR bi, where bi = SHA(sessionKey | ci-1) for i > 0; b0 = SHA(sessionKey | IV), IV = 8-bytes random value
        FileInputStream fis = new FileInputStream(file);
        //Calculate file size and round it up to multiple of 8 as that is the fixed block length
        long fileSize = file.length();
        if (fileSize % 8 != 0) {
            fileSize += 8 - (fileSize % 8);
        }
        //Send value of file size
        objOS.writeLong(fileSize);
        objOS.flush();
        //Start reading data from file 8 bytes at a time, encrypt it and send it
        boolean firstBlock = true;
        int nRead = 0;
        byte[] pi = new byte[8];
        byte[] ci = new byte[9];
        byte[] bi = new byte[8];
        byte[] ti = new byte[8];
        while ((nRead = fis.read(pi)) != -1) {
            //If the number of bytes read from file is less than 8, pad remaining length with 0
            if (nRead < 8) {
                Arrays.fill(pi, nRead, pi.length, (byte) 0);
            }
            if (firstBlock) {
                bi = gnrtIntrBlks(ivValue);
            } else {
                bi = gnrtIntrBlks(ci);
            }
            for (int i = 0; i < 8; i++) {
                ci[i] = (byte) (pi[i] ^ bi[i]);
                ti[i] = ci[i];
            }
            ci[8] = getHash(ti);
            objOS.write(ci);
            objOS.flush();
        }
        fis.close();
    }

    private byte[] gnrtIntrBlks(byte[] appendValue){
        byte[] combined = new byte[encryptionKey.length + appendValue.length];
        System.arraycopy(encryptionKey,0,combined,0         ,encryptionKey.length);
        System.arraycopy(appendValue,0,combined,encryptionKey.length,appendValue.length);
        byte[] encodedHash = digest.digest(combined);
        return Arrays.copyOf(encodedHash, 8);
    }
    private byte getHash(byte[] ci){
        byte[] hash = digest.digest(ci);
        return hash[0];
    }
}
