import java.io.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;
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

public class Main {

    String localFolderPath = "file-storage/";
    //Store 64-bit(8-bytes) session key
    private byte[] sessionKey, integrityKey, encryptionKey, ivValue;
    private Socket clientSocket;
    OutputStream outStream;
    InputStream inStream;
    DataInputStream dis;
    DataOutputStream dos;
    MessageDigest digest;
    PublicKey publicKeyCA;
    X509Certificate serverCertificate;
    ObjectInputStream objIS;
    ObjectOutputStream objOS;
    PublicKey publicKeyServer;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Main obj = new Main();
        Integer option = 0;
        Scanner sc = new Scanner(System.in);
        try{
            obj.extractCertificateFromCA();
            // open a socket to server
            obj.clientSocket = new Socket("192.168.43.46", 9000);
            //Authenticate server
            obj.authenticateServer();
            //Server authenticated, now generate session key and share it with server
            obj.generateSessionKey();
            obj.shareSessionKeyWithServer();
            do{
                System.out.println("***********************");
                System.out.println("Select from options below");
                System.out.println("1. Upload file");
                System.out.println("2. Download file");
                System.out.println("3. Exit");
                Integer selection = sc.nextInt();
                switch(selection){
                    case 1:
                        obj.writeToServer("Upload");
                        break;
                    case 2:
                        obj.writeToServer("Download");
                        break;

                    case 3:
                        option = -1;
                        obj.writeToServer("Exit");
                }
                System.out.println("\n\n\n");
            }while(option != -1);
        }
        catch(Exception e){
            e.printStackTrace();
            obj.closeCommunication();
        }
    }

    private void extractCertificateFromCA(){
        try {
            File caP = new File("Client-certs/ashkan-public.pem");
            publicKeyCA = get(caP); //public key of the CA
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

    public static X509Certificate getX509(File certloc) throws CertificateException, FileNotFoundException {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream ("/Users/anirudh/Desktop/Proj/Server/certs/mycert.pem");
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

    private void authenticateServer() throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
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
        //writeToServer("Sync");
        try {
            objOS.writeUTF("Sync");
            objOS.flush();
            serverCertificate = (X509Certificate) objIS.readObject();
            serverCertificate.verify(publicKeyCA);
            //client gets public key of server from x509 cert
            publicKeyServer = serverCertificate.getPublicKey();

        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

    private void shareSessionKeyWithServer() throws IOException, NoSuchAlgorithmException, ClassNotFoundException {
        //writeToServer("Key");
        try {
            long messageLength = "Key".length() + sessionKey.length;
            objOS.writeUTF("Key");
            objOS.flush();
            byte[] secret = encrypt(publicKeyServer, sessionKey);
            objOS.writeInt(secret.length);
            objOS.flush();
            objOS.write(secret);
            objOS.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void generateSessionKey() throws NoSuchAlgorithmException{
        digest = MessageDigest.getInstance("SHA-1");
        //Generate 16-byte long random session key
        SecureRandom random = new SecureRandom();
        sessionKey = random.generateSeed(16);
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

    private void closeCommunication() throws IOException{
        clientSocket.close();
        sessionKey = null;
    }

    private String readFromServer() throws IOException {
        inStream = clientSocket.getInputStream();
        DataInputStream dis = new DataInputStream(inStream);
        byte[] buffer = new byte[4096];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        while(dis.read(buffer) != -1) {
            baos.write(buffer);
        }
        String result = baos.toString();
        System.out.println("Server: " + result);
        return result;
    }

    private void writeToServer(String message) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        System.out.println("Client: " + message);
        if(message.equalsIgnoreCase("Exit")){
            objOS.writeUTF("Exit");
            objOS.flush();
        }
        else if(message.equalsIgnoreCase("Upload")){
            File file;
            while(true){
                System.out.println("Enter fileName: ");
                String fileName = new Scanner(System.in).nextLine();
                file = new File(localFolderPath + fileName);
                if(!file.exists()){
                    //File name wrong, file not found in directory, try again
                    System.out.println("File not found, try again...");
                    continue;
                }
                else{
                    //Send upload command to server
                    objOS.writeUTF("Upload");
                    objOS.flush();
                    break;
                }
            }
            encryptAndSend(objOS, file);
        }
        else if(message.equalsIgnoreCase("Download")){
            //Send download command to server
            objOS.writeUTF("Download");
            objOS.flush();
            String fileName;
            while(true){
                System.out.println("Enter fileName: ");
                fileName = new Scanner(System.in).nextLine();
                objOS.writeUTF(fileName);
                objOS.flush();
                String response = objIS.readUTF();
                if(response.equalsIgnoreCase("Found")){
                    break;
                }
                else{
                    //File name wrong, file not found in directory on the server, try again
                    System.out.println("File not found on the server, try again...");
                }
            }
            decryptAndStoreFile(objIS, fileName);
        }

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
                pi[i] = (byte)(ci[i] ^ bi[i]);
                ti[i] = ci[i];
            }
            if(getHash(ti)!= ci[8]){
                System.out.println("Error");
            }
            fos.write(pi);
        }
        fos.flush();
        fos.close();
    }

    private void encryptAndSend(ObjectOutputStream objOS, File file) throws IOException {
        //The encrypted block size is 8-bytes, ci = pi XOR bi, where bi = SHA(sessionKey | ci-1) for i > 0; b0 = SHA(sessionKey | IV), IV = 8-bytes random value
        FileInputStream fis = new FileInputStream(file);
        //Send file name
        objOS.writeUTF(file.getName());
        objOS.flush();
        //Calculate file size and round it up to multiple of 8 as that is the fixed block length
        long fileSize = file.length();
        if(fileSize % 8 != 0){
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
        while((nRead = fis.read(pi)) != -1) {
            //If the number of bytes read from file is less than 8, pad remaining length with 0
            if(nRead < 8){
                Arrays.fill(pi, nRead, pi.length, (byte)0 );
            }
            if(firstBlock){
                bi = gnrtIntrBlks(ivValue);
            }
            else{
                bi = gnrtIntrBlks(ci);
            }
            for(int i = 0; i < 8; i++){
                ci[i] = (byte)(pi[i] ^ bi[i]);
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