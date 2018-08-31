import java.net.*;
import java.io.*;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;
import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random ;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.time.Instant;
public class GreetingAAgent extends Thread {
	
	String skeyString;
	String na,nd,nb;
	private static final String PUBLIC_KEY_FILE = "Public.key";
    private static final String PRIVATE_KEY_FILE = "Private.key";
	    String key = "E1BB465D57CAE7ACDBBE8091F9CE83DF";
    private static final String ALGORITMO = "AES/CBC/PKCS5Padding";
    private static final String CODIFICACION = "UTF-8";
   private ServerSocket serverSocket;
   
   public GreetingAAgent(int port) throws IOException {
      serverSocket = new ServerSocket(port);
      serverSocket.setSoTimeout(10000000);
   }
   
     public GreetingAAgent(){
	   
   }

   public void run() {
      while(true) {
         try {
            System.out.println("Waiting for client on port " + 
               serverSocket.getLocalPort() + "...");
            Socket server = serverSocket.accept();
            
            System.out.println("Just connected to " + server.getRemoteSocketAddress());
			InputStream myinpstr=server.getInputStream();
            DataInputStream in = new DataInputStream(myinpstr);
            
            //System.out.println(in.readUTF());

            DataOutputStream out = new DataOutputStream(server.getOutputStream());
            /*out.writeUTF("Thank you for connecting to " + server.getLocalSocketAddress()
               + "\nGoodbye!");
             */

            out.writeUTF("Kindly Provide your Credentials");	
			GreetingAAgent greetinAgent=new GreetingAAgent();
			//String encyptedusername=in.readUTF();
			int u_l=in.readInt();
			byte[] encyptedusername= new byte[u_l];
			in.readFully(encyptedusername,0,u_l);
			System.out.println(encyptedusername);
			String username=greetinAgent.decryptData(encyptedusername);
			System.out.println(username);
			out.writeUTF("correct");
			int p_l=in.readInt();
			byte[] encyptedpassword=new byte[p_l];
			//String encyptedpassword=in.readUTF();
			in.readFully(encyptedpassword,0,p_l);
			System.out.println(encyptedpassword);
			String password=greetinAgent.decryptData(encyptedpassword);
			out.writeUTF("done");
			
			Socket client = new Socket("localhost", 1600);
			OutputStream outToServer2 = client.getOutputStream();
            DataOutputStream out2 = new DataOutputStream(outToServer2);
         
 
            InputStream inFromServer2 = client.getInputStream();
            DataInputStream in2 = new DataInputStream(inFromServer2);
			String s=in2.readUTF();
			try{
			
			if(s.equals("Kindly Provide your Credentials")){
				String AES_enc_uname=encrypt(username,key);
				System.out.println("AES encypted username is "+AES_enc_uname);
				out2.writeUTF(AES_enc_uname);
				//out2.writeUTF(username);
				s=in2.readUTF();
				if(s.equals("correct")){
					String AES_enc_pass=encrypt(password,key);
					
					System.out.println("AES encypted password is "+AES_enc_pass);
					//out2.writeUTF(password);
					out2.writeUTF(AES_enc_pass);
					Random rn = new Random();
                    int numb = rn.nextInt(10000);
                    na = String.valueOf(numb);
					String AES_enc_na=encrypt(na,key);
					out2.writeUTF(AES_enc_na);
					s=in2.readUTF();
					if(s.equals("done")){
						System.out.println("credentials have been sent to Validation Server");
					}
				}
			}
			}
			catch(Exception e){
				e.printStackTrace();
			}
			s=in2.readUTF();
			if(s.equals("true")){
				out.writeUTF("validated");
			}
			else{
				out.writeUTF("notvalidated");
			}
			
			
			
            
            server.close();
            
         }catch(SocketTimeoutException s) {
            System.out.println("Socket timed out!");
            break;
         }catch(IOException e) {
            e.printStackTrace();
            break;
         }
      }
   }
   
   public static void main(String [] args) {
      int port = Integer.parseInt(args[0]);
      try {
         Thread t = new GreetingAAgent(port);
         t.start();
      }catch(IOException e) {
         e.printStackTrace();
      }
   }
    public String decryptData(byte[] data) throws IOException {
  System.out.println("\n----------------DECRYPTION STARTED------------");
  System.out.println(data);
  byte[] descryptedData = null;
  //byte[] d1= data.getBytes();
  System.out.println(data);
  
  try {
   PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE);
   Cipher cipher = Cipher.getInstance("RSA");
   cipher.init(Cipher.DECRYPT_MODE, privateKey);
   descryptedData = cipher.doFinal(data);
   System.out.println("Decrypted Data: " + new String(descryptedData));
   
  } catch (Exception e) {
   e.printStackTrace();
   System.out.println(e.getMessage());
  } 
  
  System.out.println("----------------DECRYPTION COMPLETED------------");
  String s = new String(descryptedData);  
  return s;
 }
   
   public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
  FileInputStream fis = null;
  ObjectInputStream ois = null;
  try {
   fis = new FileInputStream(new File(fileName));
   ois = new ObjectInputStream(fis);
   
   BigInteger modulus = (BigInteger) ois.readObject();
      BigInteger exponent = (BigInteger) ois.readObject();
   
      //Get Private Key
      RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
      KeyFactory fact = KeyFactory.getInstance("RSA");
      PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
            
      return privateKey;
      
  } catch (Exception e) {
   e.printStackTrace();
  }
  finally{
   if(ois != null){
    ois.close();
    if(fis != null){
     fis.close();
    }
   }
  }
  return null;
 }
 
public static String encrypt(String plaintext, String key)throws NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeyException, IllegalBlockSizeException,BadPaddingException, IOException{
	byte[] raw = DatatypeConverter.parseHexBinary(key);
	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	Cipher cipher = Cipher.getInstance(ALGORITMO);
	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
	byte[] cipherText = cipher.doFinal(plaintext.getBytes(CODIFICACION));
	byte[] iv = cipher.getIV();
	ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
	outputStream.write(iv);
	outputStream.write(cipherText);
	byte[] finalData = outputStream.toByteArray();
	String encodedFinalData = DatatypeConverter.printBase64Binary(finalData);
	return encodedFinalData;
}

  public static String decrypt(String encodedInitialData, String key)throws InvalidKeyException, IllegalBlockSizeException,BadPaddingException, UnsupportedEncodingException,NoSuchAlgorithmException, NoSuchPaddingException,InvalidAlgorithmParameterException{
	byte[] encryptedData = DatatypeConverter.parseBase64Binary(encodedInitialData);
	byte[] raw = DatatypeConverter.parseHexBinary(key);
	SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
	Cipher cipher = Cipher.getInstance(ALGORITMO);
	byte[] iv = Arrays.copyOfRange(encryptedData, 0, 16);
	byte[] cipherText = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
	IvParameterSpec iv_specs = new IvParameterSpec(iv);
	cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv_specs);
	byte[] plainTextBytes = cipher.doFinal(cipherText);
	String plainText = new String(plainTextBytes);
	return plainText;
	}
	
	    public byte[] encryptData(String data) throws IOException {
  System.out.println("\n----------------ENCRYPTION STARTED------------");
  
  System.out.println("Data Before Encryption :" + data);
  byte[] dataToEncrypt = data.getBytes();
  byte[] encryptedData = null;
  try {
   PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
   Cipher cipher = Cipher.getInstance("RSA");
   cipher.init(Cipher.ENCRYPT_MODE, pubKey);
   encryptedData = cipher.doFinal(dataToEncrypt);
   System.out.println("Encryted Data: " + encryptedData);
   
  } catch (Exception e) {
   e.printStackTrace();
  } 
  
  System.out.println("----------------ENCRYPTION COMPLETED------------");  
  return encryptedData;
 }
 public PublicKey readPublicKeyFromFile(String fileName) throws IOException{
  FileInputStream fis = null;
  ObjectInputStream ois = null;
  try {
   fis = new FileInputStream(new File(fileName));
   ois = new ObjectInputStream(fis);
   
   BigInteger modulus = (BigInteger) ois.readObject();
      BigInteger exponent = (BigInteger) ois.readObject();
   
      //Get Public Key
      RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory fact = KeyFactory.getInstance("RSA");
      PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
            
      return publicKey;
      
  } catch (Exception e) {
   e.printStackTrace();
  }
  
  return null;
}
   
}