# JWT REST Service Example

This REST Service allows users to create accounts, storing their passwords hashed in a database.  Once successfully logged in, users are issued a [JWT](https://jwt.io/).  Users can also delete their accounts.

Note: User's passwords are salted and hashed before being inserted into the database.

## Project Setup

* Eclipse Java EE Oxygen
* Java 9.0.4
* Tomcat server 8.5
* MySQL Database

## REST Service

**REST Endpoint:** `/jwt_auth_srv/rest/`

**Swagger.json:** `/jwt_auth_srv/rest/swagger.json`

**Swagger UI:** `/jwt_auth_srv/swagger_ui/index.html`

### Endpoints

* POST `/login` - Users log in

> **Request:**
> 
> ```
> {
>   "user": "string",
>   "password": "string"
> }
> ```
> 
> **Response:**
> 
> | HTTP Response Code | Response            |
> |:------------------:|:-------------------:|
> | 200                | JWT Token           |
> | 403                | Invalid credentials |

* POST `/new_user` - Create a new user

> **Request:**
> 
> ```
> {
>   "user": "string",
>   "password": "string"
> }
> ```
> 
> **Response:**
> 
> | HTTP Response Code | Response                                   |
> |:------------------:|:------------------------------------------:|
> | 201                | User created successfully                  |
> | 403                | Invalid credentials or user already exists |

* POST `/delete_user` - Delete a user

> **Request:**
> 
> ```
> {
>   "user": "string",
>   "password": "string"
> }
> ```
> 
> **Response:**
> 
> | HTTP Response Code | Response                  |
> |:------------------:|:-------------------------:|
> | 200                | User successfully deleted |
> | 403                | Invalid credentials       |

## JWT

The following are the contents and of the JWT that the service produces:

**JWT Secret:** secret

Header:

```
{
  "typ": "JWT",
  "alg": "HS256"
}
```

Payload:

```
{
  "iss": "JWTAuth",
  "id": User's ID,
  "exp": One week after login,
  "user": username,
  "iat": Login date
}
```

## Database

The following are the database settings of this service:

* **User:** jwtauth
* **Password:** w|'Dzh20~d&18/sK
* **Schema:** jwtauth

### Tables

```
CREATE TABLE `auth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` varchar(255) NOT NULL,
  `password` binary(32) NOT NULL,
  `salt` binary(32) NOT NULL,
  `alg` varchar(15) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq` (`user`)
);
```

* **id** - user id
* **user** - name of the user
* **password** - hashed password
* **salt** - the salt associated with the password
* **alg** - hash algorithm
