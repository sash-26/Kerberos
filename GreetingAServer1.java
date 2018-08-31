import java.net.*;
import java.io.*;
import javax.swing.*;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Random ;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class GreetingAServer extends Thread {
   private ServerSocket serverSocket;
   String skeyString;
   static byte[] raw;
   byte[] skey = new byte[1000];
   
   public GreetingAServer(int port) throws IOException {
      serverSocket = new ServerSocket(port);
      serverSocket.setSoTimeout(10000000);
   }

   public void run() {
      while(true) {
         try {
            System.out.println("Waiting for client on port " + 
               serverSocket.getLocalPort() + "...");
            Socket server = serverSocket.accept();
            
            System.out.println("Just connected to " + server.getRemoteSocketAddress());
            DataInputStream in = new DataInputStream(server.getInputStream());
            
            //System.out.println(in.readUTF());

            DataOutputStream out = new DataOutputStream(server.getOutputStream());
            /*out.writeUTF("Thank you for connecting to " + server.getLocalSocketAddress()
               + "\nGoodbye!");
             */
			 
			generateSymmetricKey();
            out.writeUTF("Kindly Provide your Credentials");
            out.writeInt(raw.length);
			out.write(raw);		
			System.out.println("raw is "+raw);
            int t1=in.readInt();
            byte[] enc_u_name=new byte[t1];			
			//String username=in.readUTF();
			//System.out.println(username);
			in.readFully(enc_u_name,0,t1);
			out.writeUTF("correct");
			int t2=in.readInt();
			byte[] enc_p=new byte[t2];
			//String password=in.readUTF();
			in.readFully(enc_p,0,t2);
			out.writeUTF("done");
			byte[] uname=decrypt(raw,enc_u_name);
			byte[] passw=decrypt(raw,enc_p);
			String username=uname.toString();
			String password=passw.toString();
			System.out.println(username);
			System.out.println(password);
			if(username.equals("sachin") && password.equals("sharma")){
				out.writeUTF("true");
			}
			else{
				out.writeUTF("false");
			}
			
			
            
            server.close();
            
         }catch(SocketTimeoutException s) {
            System.out.println("Socket timed out!");
            break;
         }catch(IOException e) {
            e.printStackTrace();
            break;
         }
		 catch(Exception e){
			e.printStackTrace(); 
		 }
      }
   }
   
   public static void main(String [] args) {
      int port = Integer.parseInt(args[0]);
      try {
         Thread t = new GreetingAServer(port);
         t.start();
      }catch(IOException e) {
         e.printStackTrace();
      }
   }
   
void generateSymmetricKey() {
try {
Random r = new Random();
int num = r.nextInt(10000);
String knum = String.valueOf(num);
byte[] knumb = knum.getBytes();
skey=getRawKey(knumb);
skeyString = new String(skey);
System.out.println("AES Symmetric key = "+skeyString);
}
catch(Exception e) {
System.out.println(e);
}
}
private static byte[] getRawKey(byte[] seed) throws Exception {
KeyGenerator kgen = KeyGenerator.getInstance("AES");
SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
sr.setSeed(seed);
kgen.init(128, sr); // 192 and 256 bits may not be available
SecretKey skey = kgen.generateKey();
raw = skey.getEncoded();
return raw;
}
private static byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
	System.out.println("Data to be decrypted is "+encrypted);
SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.DECRYPT_MODE, skeySpec);
byte[] decrypted = cipher.doFinal(encrypted);
System.out.println("decrypted data is "+decrypted);
return decrypted;
}
}