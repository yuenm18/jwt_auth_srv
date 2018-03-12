package com.my.resources;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.log4j.Logger;

import com.my.api.AuthenticationApi;
import com.my.model.Login;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponses;
import io.swagger.annotations.ApiResponse;


/**
 * REST Service for authenticating users
 * 
 * 
 * /login - log in a user
 * /new_user - create a new user
 * /delete_user - delete a user
 * 
 * 
 * @author MatthewYuen
 *
 */
@Api(value = "Authentication")
@Path("/")
public class Authentication {


	private final String BAD_CREDENTIALS = "Invalid user or password";
	private final String BAD_USER_DATA = "User must be between 1-20 characters and password must be between 4-20 characters";
	
	

	@Path("login")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@ApiOperation(value = "Login a user",
    	notes = "Generates a JWT for the user")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "JWT"),
		      @ApiResponse(code = 403, message = "Login error") })
	public Response login(Login loginInfo) {
		// verify parameters
		if (!verifyLoginFields(loginInfo)) {
			return Response.status(Status.FORBIDDEN).entity(BAD_CREDENTIALS).build();
		}
		
		// log in and get jwt from the user
		String jwt = new AuthenticationApi().login(loginInfo);
		
		// invalid login
		if (jwt == null) {
			return Response.status(Status.FORBIDDEN).entity(BAD_CREDENTIALS).build();
		}
			
		return Response.status(Status.OK).entity(jwt).build();
	}
	
	@Path("new_user")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.TEXT_PLAIN)
	@ApiOperation(value = "Creates a new user",
		notes = "Creates a user with the given username and password")
	@ApiResponses(value = { @ApiResponse(code = 201, message = "Successfully created user"),
		      @ApiResponse(code = 403, message = "Creation error") })
	public Response newUser(Login loginInfo) {
		// verify parameters
		if (!verifyLoginFields(loginInfo)) {
			return Response.status(Status.FORBIDDEN).entity(BAD_USER_DATA).build();
		}
		
		// try create user
		if (new AuthenticationApi().newUser(loginInfo)) {
			return Response.status(Status.CREATED).entity("Successfully created user '" + loginInfo.getUser() + "'").build();
		}
		else {
			return Response.status(Status.FORBIDDEN).entity("User: '"+loginInfo.getUser()+"' already exists").build();
		}
	}
	
	@Path("delete_user")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.TEXT_PLAIN)
	@ApiOperation(value = "Deletes a user",
    	notes = "Deletes the user from the database")
	@ApiResponses(value = { @ApiResponse(code = 200, message = "Successfully deleted user"),
			@ApiResponse(code = 403, message = "Deletion error") })
	public Response deleteUser(Login loginInfo) {
		// verify parameters
		if (!verifyLoginFields(loginInfo)) {
			return Response.status(Status.FORBIDDEN).entity(BAD_CREDENTIALS).build();
		}
		
		// try delete user
		if (new AuthenticationApi().deleteUser(loginInfo)) {
			return Response.status(Status.OK).entity("Successfully deleted user '" + loginInfo.getUser() + "'").build();
		}
		else {
			return Response.status(Status.FORBIDDEN).entity(BAD_CREDENTIALS).build();
		}
	}
	
	/**
	 * Used for input validation
	 * 
	 * 
	 * Checks if username is between 1 and 20 chars and password is between 4 and 20 chars
	 * Checks if username and password contain only printable characters
	 * 
	 * @param loginInfo User's credentials
	 * @return Whether or not they are valid
	 */
	private boolean verifyLoginFields(Login loginInfo) {
		Pattern userPattern = Pattern.compile("^\\p{Print}{1,20}$");
		Pattern passwordPattern = Pattern.compile("^\\p{Print}{4,20}$");
		
		Matcher userMatcher = userPattern.matcher(loginInfo.getUser());
		Matcher passwordMatcher = passwordPattern.matcher(loginInfo.getUser());
		
		return userMatcher.matches() && passwordMatcher.matches();
	}
}
