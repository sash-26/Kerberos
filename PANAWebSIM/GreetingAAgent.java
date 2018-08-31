import java.net.*;
import java.io.*;

public class GreetingAAgent extends Thread {
   private ServerSocket serverSocket;
   
   public GreetingAAgent(int port) throws IOException {
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

            out.writeUTF("Kindly Provide your Credentials");	
			String username=in.readUTF();
			//System.out.println(username);
			out.writeUTF("correct");
			String password=in.readUTF();
			out.writeUTF("done");
			
			Socket client = new Socket("localhost", 1600);
			OutputStream outToServer2 = client.getOutputStream();
            DataOutputStream out2 = new DataOutputStream(outToServer2);
         
 
            InputStream inFromServer2 = client.getInputStream();
            DataInputStream in2 = new DataInputStream(inFromServer2);
			
			String s=in2.readUTF();
			if(s.equals("Kindly Provide your Credentials")){
				out2.writeUTF(username);
				s=in2.readUTF();
				if(s.equals("correct")){
					out2.writeUTF(password);
					s=in2.readUTF();
					if(s.equals("done")){
						System.out.println("credentials have been sent to Validation Server");
					}
				}
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
}