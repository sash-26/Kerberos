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

public class GreetingAAgent extends Thread {
	String skeyString;
	private static final String PUBLIC_KEY_FILE = "Public.key";
     private static final String PRIVATE_KEY_FILE = "Private.key";
 
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
				int count=in2.readInt();
				byte[] raw=new byte[count];
				in2.readFully(raw,0,count);
				System.out.println("raw is"+raw);
				byte[] AES_enc_uname=encrypt(raw,username.getBytes());
				System.out.println("AES encypted username is "+AES_enc_uname);
				out2.writeInt(AES_enc_uname.length);
				out2.write(AES_enc_uname);
				//out2.writeUTF(username);
				s=in2.readUTF();
				if(s.equals("correct")){
					byte[] AES_enc_pass=encrypt(raw,password.getBytes());
					System.out.println("AES encypted password is "+AES_enc_pass);
					out2.writeInt(AES_enc_pass.length);
					//out2.writeUTF(password);
					out2.write(AES_enc_pass);
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
				//out.writeUTF("validated");
				Socket client2 = new Socket("localhost", 1800);
				OutputStream outToServer3 = client2.getOutputStream();
                DataOutputStream out3 = new DataOutputStream(outToServer3);
         
 
                InputStream inFromServer3 = client2.getInputStream();
                DataInputStream in3 = new DataInputStream(inFromServer3);
				
				String tt=in3.readUTF();
				if(tt.equals("continue")){
					out.writeUTF("validated");
				}
				else{
					out.writeUTF("notvalidated");
				}
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
 
 private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
byte[] encrypted = cipher.doFinal(clear);
return encrypted;
}
}