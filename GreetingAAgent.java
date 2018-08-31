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
    private static ServerSocket serverSocket;
    private Socket server; 
   public GreetingAAgent(Socket server) throws IOException {
	this.server=server;  
   }
    public GreetingAAgent(){
	   
   }

   public void run() {
         try {
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
		    int random_l=in.readInt();
			byte[] encr_random=new byte[random_l];
			in.readFully(encr_random,0,random_l);
			String random_num=greetinAgent.decryptData(encr_random);
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
				String returned_na=in2.readUTF();
				//out.writeUTF("validated");
				if(na.equals(returned_na)){
				Socket client2 = new Socket("localhost", 1800);
				OutputStream outToServer3 = client2.getOutputStream();
                DataOutputStream out3 = new DataOutputStream(outToServer3);
                
				

                InputStream inFromServer3 = client2.getInputStream();
                DataInputStream in3 = new DataInputStream(inFromServer3);
				try{
				String AES_enc_una=encrypt(username,key);
				out3.writeUTF(AES_enc_una);
				Random rn2 = new Random();
                int numb2 = rn2.nextInt(10000);
                nd = String.valueOf(numb2);
				String AES_enc_nd=encrypt(nd,key);
				out3.writeUTF(AES_enc_nd);
				String timeStamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
				String AES_enc_timestamp=encrypt(timeStamp,key);
				out3.writeUTF(AES_enc_timestamp);
				String enc_randomnum=encrypt(random_num,key);
				out3.writeUTF(enc_randomnum);
				String tt=in3.readUTF();
				
				if(tt.equals("break")){
					out.writeUTF("notvalidated");
				}
				else{
					out.writeUTF("validated");
					String fi_tt=decrypt(tt,key);
					System.out.println(fi_tt);
					String[] parts = fi_tt.split("//////////");
					Random rn3 = new Random();
                    int numb3= rn3.nextInt(10000);
                    nb = String.valueOf(numb3);  
					System.out.println(parts.length);
					String my_temp="validated"+"//////////"+nb+"//////////"+parts[4];
					byte[] enc_my_temp=encryptData(my_temp);
					out.writeInt(enc_my_temp.length);
					out.write(enc_my_temp);
					String final_session_data=decrypt(parts[4],key);
					String[] pt=final_session_data.split("//////////");
			     	String kab=pt[1];
					
				}
				}
				catch(Exception e){
					e.printStackTrace();
				}
				}
				else{
					out.writeUTF("na doesn't match");
				}
			}
			else{
				out.writeUTF("notvalidated");
			}
			
			
			
            
            server.close();
            
         }catch(SocketTimeoutException s) {
            System.out.println("Socket timed out!");
         }catch(IOException e) {
            e.printStackTrace();
         }
   }
   
   public static void main(String [] args) {
      int port = Integer.parseInt(args[0]);
	  try {
	  serverSocket = new ServerSocket(port);
      serverSocket.setSoTimeout(10000000);
	  int count=0;
	  while(true){
         System.out.println("count is "+count);
		 Socket server = serverSocket.accept();
         Thread t = new GreetingAAgent(server);
         t.start();
		 count++;
	  }
	  }
	  catch(IOException e) {
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