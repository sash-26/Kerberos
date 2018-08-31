import java.net.*;
import java.io.*;
import java.util.Scanner;
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
public class GreetingClient {
	
		private static final String PUBLIC_KEY_FILE = "Public.key";
        private static final String PRIVATE_KEY_FILE = "Private.key";
	    private static final String key = "E1BB465D57CAE7ACDBBE8091F9CE83DF";
        private static final String ALGORITMO = "AES/CBC/PKCS5Padding";
        private static final String CODIFICACION = "UTF-8";
		
	
	
        
   public static void main(String [] args) {


	 
      String serverName = args[0];
      int port = Integer.parseInt(args[1]);
      try {
         System.out.println("Connecting to " + serverName + " on port " + port);
         Socket client = new Socket(serverName, port);
         
         System.out.println("Just connected to " + client.getRemoteSocketAddress());
         OutputStream outToServer = client.getOutputStream();
         DataOutputStream out = new DataOutputStream(outToServer);
         
 
         InputStream inFromServer = client.getInputStream();
         DataInputStream in = new DataInputStream(inFromServer);
		 String temp;
		 GreetingClient greetingClient=new GreetingClient();
		 
		Scanner scanner = new Scanner(System.in);
        String s=in.readUTF();
         if(s.equals("Kindly Provide your Credentials")){
         System.out.println("Server says " + s);
		 System.out.println("Provide Your Username ");
		 String t1=scanner.next();
		  byte[] encryptedusername = greetingClient.encryptData(t1);
		  //String e_u=encryptedusername.toString();
		  //System.out.println(e_u);
         out.writeInt(encryptedusername.length);
		 out.write(encryptedusername);
		 //outToServer.write(encryptedusername);
          s=in.readUTF();
           if(s.equals("correct")){
			   System.out.println("Provide Your Password ");
			   String t2=scanner.next();
			   byte[] encryptedPass = greetingClient.encryptData(t2);
			   //String e_p=encryptedPass.toString();
               out.writeInt(encryptedPass.length);
			   out.write(encryptedPass);
			   //outToServer.write(encryptedPass);
			   System.out.println("Provide 5 digits random numbers");
			   String t3=scanner.next();
			   byte[] encr_random=greetingClient.encryptData(t3);
			   out.writeInt(encr_random.length);
			   out.write(encr_random);
               s=in.readUTF();
               if(s.equals("done")){
                  System.out.println("You Are Connected To Agent. Your Query is being proccessed!Wait!wait!\n");
				  while(true){
					  temp=in.readUTF();
					  
					  if(temp.equals("validated")){
						  int mycnt=in.readInt();
						  byte [] enc_data=new byte[mycnt];
						  in.readFully(enc_data,0,mycnt);
						  String dec_data=greetingClient.decryptData(enc_data);
						  String[] parts = dec_data.split("//////////");
						  String hh=parts[2];
						  System.out.println(hh);
						  String final_session_data=decrypt(hh,key);
						  System.out.println(final_session_data);
						  String[] pt=final_session_data.split("//////////");
						  String kab=pt[1];
						  System.out.println("Session Key Between a to b is "+kab);
						  System.out.println("You are validated");
						  break;
					  }
					  else if(temp.equals("notvalidated")){
						  System.out.println("Your credentials are wrong");
						  break;
					  }
					  else if(temp.equals("na doesn't match")){
						  System.out.println("Failed! na mismatching");
						  break;
					  }
					  else{continue;
					  }
				  }
                }
             }
          }
         client.close();
      }catch(IOException e) {
         e.printStackTrace();
      }
	  catch(Exception e){
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
}
