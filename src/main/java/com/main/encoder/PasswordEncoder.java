package com.main.encoder;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncoder {

	 public static void main(String[] args) {
		 BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		 String pwd1 =encoder.encode("chintu@1995");
		 String pwd2 =encoder.encode("manoj@1995");
		 String pwd3 =encoder.encode("mukti@1995");
		 String pwd4 =encoder.encode("raja@1995");
		 
		 System.out.println(pwd1);
		 System.out.println(pwd2);
		 System.out.println(pwd3);
		 System.out.println(pwd4);
	}
		
	 
}
