package com.my.util;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;

import io.swagger.jaxrs.config.BeanConfig;

/**
 * Swagger Config
 * 
 * @author MatthewYuen
 *
 */
public class SwaggerBootstrap extends HttpServlet {

	private static final long serialVersionUID = 249901799890820541L;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);

		BeanConfig beanConfig = new BeanConfig();
		beanConfig.setVersion("1.0");
		beanConfig.setSchemes(new String[] { "http" });
		//beanConfig.setHost("localhost:8080");
		beanConfig.setBasePath("/jwt_auth_srv/rest/");
		beanConfig.setResourcePackage("com.my.resources");
		beanConfig.setTitle("JWT REST Service");
		beanConfig.setDescription("This REST Service distributes JWT tokens.  Functions: Create a user, delete a user, log in");
		beanConfig.setScan(true);
	}
}
