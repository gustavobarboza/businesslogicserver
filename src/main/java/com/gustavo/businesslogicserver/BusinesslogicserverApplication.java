package com.gustavo.businesslogicserver;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.sql.SQLOutput;

@SpringBootApplication
public class BusinesslogicserverApplication {

    public static void main(String[] args) {
        SpringApplication.run(BusinesslogicserverApplication.class, args);
    }
}
