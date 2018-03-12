package com.my.api;

import javax.ws.rs.WebApplicationException;

/**
 * Abstract class to connect to the database
 * Provides necessary configuration for the database connection
 * 
 * @author MatthewYuen
 *
 */
public abstract class QueryApi {
	protected static final String DRIVER_CLASS = "com.mysql.cj.jdbc.Driver";
	protected static final String URL = "jdbc:mysql://localhost:3306/jwtauth";
	protected static final String USER = "jwtauth";
	protected static final String PASSWORD = "w|'Dzh20~d&18/sK";
	
	public QueryApi() {
		try {
			Class.forName(DRIVER_CLASS);
		}
		catch(ClassNotFoundException e) {
			e.printStackTrace();
			throw new WebApplicationException(e);
		}
	}

}
