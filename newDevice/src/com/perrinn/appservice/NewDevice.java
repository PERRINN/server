package com.perrinn.appservice;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class NewDevice implements RequestHandler<String, String> {

	private SecureRandom r;
	private String keyData;
	
    @Override
    public String handleRequest(String input, Context context) {
        context.getLogger().log("Input: " + input);
        try {
        	this.keyData = null;
        	this.r = SecureRandom.getInstance("SHA1PRNG");
        	this.keyData = String.valueOf(this.r.nextLong());
        	String tmp = input + this.keyData;
        	
        	MessageDigest m = MessageDigest.getInstance("SHA-1");
        	m.reset();
        	m.update(tmp.getBytes());
        	byte[] digest = m.digest();
        	BigInteger bi = new BigInteger(1, digest);
        	this.keyData = bi.toString(16);
        	while(this.keyData.length() < 32) {
        		this.keyData = "0" + this.keyData;
        	}
        }
        catch(Exception ex) {
        	context.getLogger().log("Exception: " + ex.toString());
        	this.keyData = null;
        }

        // TODO: implement your handler
        return this.keyData;
    }

}
