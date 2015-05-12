## Important Info
This project is a Django web application that provides identity management tools for basic LDAPs.  The initial capabilities were developed for self-service password reset and password recovery.  One of the primary purposes of this project was to learn both python (v2.x) and the Django web framework.  By no means should this project be regarded as developed with "best practices."  As time marches on, this project may or may not be refactored as my knowledge and experience evolve (buyer beware!). 

## Dev Environment Setup and Dependencies
This project was created by making use of virtualenv and virtualenvwrapper.  It was originally developed using Python 2.7.x and DJango 1.8.  Pip is also used to manage dependencies.  A requirements.txt file is included in this repository.

## Running and Testing
The ss application depends on a config.ini configuration file that keeps sensitive connection parameters to both the LDAP and mail.  To get started, here is a template for that file.  Save it in the ss subdirectory.
```
[default]

ldap_host={ enter host here }
ldap_manager={ dn of Directory Manager }
ldap_manager_cred={ Directory Manager Password }
ldap_admin={ dn of admin user }
ldap_cred={ admin password }
dn={ base search dn for finding users }

email_server={ email server host }
email_port={ port }
email_local_hostname{ email local hostname }

email_username= { username }
email_password={ password }
email_fromaddr={ from addr }

```
You will want to have an LDAP to test against.  I recommend installing and configuring one that you have full control over.

## More to come...
