/*************************************************************/
/* Copyright (C) 2016, PERRINN Limited.  All Rights Reserved */
/*                                                           */
/* This software is distributed under the Apache 2.0 license */
/* For usage rights, please contact contact@perrinn.com      */
/*                                                           */
/*************************************************************/
/* This module developed by Christopher Moran                */
/*************************************************************/

/*************************************************************/
/*                     HOW THIS WORKS                        */
/*                                                           */
/* The design brief calls for the device to be the key for   */
/* authentication, using a MAC or IMEI string as it's key.   */
/* To make this a little more obscure and harder to predict, */
/* we generate a SecureRandom and attach it to the string as */
/* a one-time key.  Then a hash is performed on this value   */
/* to create a password which is essentially random.         */
/* Both strings are committed to the Device table, and the   */
/* pass is returned to the caller.                           */
/*************************************************************/


package com.perrinn.appservice;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;


public class NewDevice implements RequestHandler<String, String> {

	private SecureRandom r;
	private String keyData;
	private Connection conn;
	private String connString;
	private String userId;
	private String password;
	private PreparedStatement stmt;

	public NewDevice() {
		// We have to extract the local credentials from the environment
		// Because as a lambda function, there is no way to use a
		// properties file

		// Be aware that because Lambda is essentially run from a Docker container
		// (nothing wrong with that), our constructor might be long-lived.  Only
		// do essential inits here, and actual data manipulations in handleRequest()

		this.conn = null;
		this.connString = "jdbc:mysql://database.perrinnapp.net/appdata";
		this.userId = null;
		this.password = null;
		this.stmt = null;
	}
	
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

			// OK, so we now have a key and a pass to 
			// store in the DB and return to the user
			Class.forName("com.mysql.jdbc.Driver");
			this.conn = DriverManager.getConnection(this.connString, this.userId, this.password);
			this.conn.open();
			this.stmt = this.conn.prepareStatement("insert into devices(deviceId,deviceKey) values(?,?)");
			this.stmt.setString(1, input);
			this.stmt.setString(2, this.keyData);
			this.stmt.addBatch();
			this.stmt.executeBatch();
			this.stmt.close();
			this.conn.close();
        }
        catch(Exception ex) {
        	context.getLogger().log("Exception: " + ex.toString());
        	this.keyData = null;
        }

        return this.keyData;
    }

}
