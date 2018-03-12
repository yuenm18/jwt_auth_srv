package com.my.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.Date;
import java.util.Arrays;

import javax.ws.rs.WebApplicationException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import com.my.model.Login;

/**
 * Queries the database
 * 
 * Operations:
 * Create new user
 * Delete a user
 * Login a user
 * 
 * @author MatthewYuen
 *
 */
public class AuthenticationApi extends QueryApi {

	protected static final String LOGIN_QUERY = "SELECT * FROM auth WHERE user = ?";
	protected static final String NEW_USER_QUERY = "INSERT INTO auth(user, password, salt, alg) VALUES(?,?,?,?)";
	protected static final String DELETE_USER_QUERY = "DELETE FROM auth WHERE id = ?";
	
	private static final String JWT_SECRET = "secret";
	private static final String ISSUER = "JWTAuth";
	private static final String PASSWORD_HASH_ALGORITHM = "SHA-256";
	
	public static final int INVALID_CREDENTIALS = -1;
	
	/**
	 * Logs a user into system
	 * 
	 * @param loginInfo User credentials
	 * @return JWT for user
	 */
	public String login(Login loginInfo) {
		int id = INVALID_CREDENTIALS;
		
		// check credentials
		try (Connection connection = DriverManager.getConnection(URL, USER, PASSWORD)) {
			id = authenticateUser(connection,loginInfo);
			if (id == INVALID_CREDENTIALS) {
				return null;
			}
		}
		// Server Error
		catch(Exception e) {
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
		
		// Generate the jwt
		try {
			// get current date
			Date iat = new Date();
			// get week from current date 7 day/week*24 hours/day*60 mins/hour*60 secs/min
			Date exp = new Date(iat.getTime()+7*24*60*60);
			
			// Use HMAC-256
		    Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
		    
		    
		    // build JWT
		    String jwt = JWT.create()
		        .withIssuer(ISSUER)
		        .withClaim("user", loginInfo.getUser())
		        .withClaim("id", id)
		        .withIssuedAt(iat)
		        .withExpiresAt(exp)
		        .sign(algorithm);
		    
		    return jwt;
		    
		}
		// Server Error
		catch (Exception e){
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
	}
	
	/**
	 * Create new user
	 * 
	 * @param loginInfo User credentials
	 * @return true if created successfully, false if duplicate users exist
	 */
	public boolean newUser(Login loginInfo) {
		try (Connection connection = DriverManager.getConnection(URL, USER, PASSWORD);
			CallableStatement call = connection.prepareCall(NEW_USER_QUERY)) {
			
			// generate a random salt
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[32];
			random.nextBytes(salt);
			
			// generate the password hash
			byte[] hash = hashPassword(loginInfo.getPassword(), salt);
			
			// generate the query statement
			call.setString(1, loginInfo.getUser());
			call.setBytes(2, hash);
			call.setBytes(3, salt);
			call.setString(4, PASSWORD_HASH_ALGORITHM);
			
			// execute the query
			call.execute();
		}
		// Duplicate Users
		catch(SQLIntegrityConstraintViolationException e) {
			e.printStackTrace();
			return false;
		}
		// Server Error
		catch(Exception e) {
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
		return true;
	}
	
	/**
	 * Deletes a user
	 * 
	 * @param loginInfo User Credentials
	 * @return true if user is deleted successfully, false if invalid credentials
	 */
	public boolean deleteUser(Login loginInfo) {		
		try (Connection connection = DriverManager.getConnection(URL, USER, PASSWORD)) {
			
			// transaction begin
			connection.setAutoCommit(false);
			
			try (CallableStatement call = connection.prepareCall(DELETE_USER_QUERY)){
				
				// verify user's credentials and get their id
				int id = authenticateUser(connection, loginInfo);
				
				// check user credentials
				if (id == INVALID_CREDENTIALS) {
					return false;
				}
				
				// generate the delete query
				call.setInt(1, id);
				
				// execute the query
				call.execute();
			}
			// Server Error
			catch (Exception e) {
				connection.rollback();
				connection.setAutoCommit(true);
				throw e;
			}
			// no errors so commit changes
			connection.commit();
			connection.setAutoCommit(true);
		}
		// Server Error
		catch (SQLException e) {
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
		return true;
	}
	
	/**
	 * Checks if user credentials are correct
	 * 
	 * @param connection Connection to the database
	 * @param loginInfo User credentials
	 * @return the id of the user if the credentials are correct or INVALID_CREDENTIALS if not
	 */
	private int authenticateUser(Connection connection, Login loginInfo) {
		
		int response = INVALID_CREDENTIALS;
		
		try (PreparedStatement preparedStatement = connection.prepareStatement(LOGIN_QUERY)) {
			// generate the query
			preparedStatement.setString(1, loginInfo.getUser());
			
			// execute the query
			ResultSet resultSet = preparedStatement.executeQuery();

			// check if hashes match
			// if there are any results
			if (resultSet.next()) {
				// generate the hash
				byte[] testHash = hashPassword(loginInfo.getPassword(), resultSet.getBytes("salt"));
				byte[] hash = resultSet.getBytes("password");
				
				// check the hash
				if (Arrays.equals(testHash,hash)) {
					response = resultSet.getInt("id");
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
		return response;
	}
	
	
	/**
	 * Hashes a password
	 * Prepends the salt to the password and then hashes it with PASSWORD_HASH_ALGORITHM
	 * 
	 * @param passwordStr The password as a string
	 * @param salt the salt as an array of bytes
	 * @return a byte array of the hash
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] hashPassword(String passwordStr, byte[] salt) throws NoSuchAlgorithmException {
		MessageDigest hasher = MessageDigest.getInstance(PASSWORD_HASH_ALGORITHM);
		byte[] password = passwordStr.getBytes(StandardCharsets.UTF_8);
		byte[] saltPassword = new byte[salt.length + password.length];
		System.arraycopy(salt, 0, saltPassword, 0, salt.length);
		System.arraycopy(password, 0, saltPassword, salt.length, password.length);
		return hasher.digest(saltPassword);
	}
}
