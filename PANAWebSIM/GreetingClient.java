import java.net.*;
import java.io.*;
import java.util.Scanner;
public class GreetingClient {

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
		 
		Scanner scanner = new Scanner(System.in);
        String s=in.readUTF();
         if(s.equals("Kindly Provide your Credentials")){
         System.out.println("Server says " + s);
		 System.out.println("Provide Your Username ");
		 String t1=scanner.next();
         out.writeUTF(t1);
          s=in.readUTF();
           if(s.equals("correct")){
			   System.out.println("Provide Your Password ");
			   String t2=scanner.next();
               out.writeUTF(t2);
               s=in.readUTF();
               if(s.equals("done")){
                  System.out.println("You Are Connected To Agent. Your Query is being proccessed!Wair!wait!\n");
				  while(true){
					  temp=in.readUTF();
					  
					  if(temp.equals("validated")){
						  System.out.println("You are validated");
						  break;
					  }
					  else if(temp.equals("notvalidated")){
						  System.out.println("Your credentials are wrong");
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
   }
}
