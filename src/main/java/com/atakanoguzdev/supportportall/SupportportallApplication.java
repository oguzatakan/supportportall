package com.atakanoguzdev.supportportall;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.io.File;

import static com.atakanoguzdev.supportportall.constant.FileConstant.USER_FOLDER;


@SpringBootApplication
public class SupportportallApplication {

	public static void main(String[] args) {
		SpringApplication.run(SupportportallApplication.class, args);
		new File(USER_FOLDER).mkdirs();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
