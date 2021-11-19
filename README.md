tcp80x
=======
tcp80x is an HTTP server with some pseudo-CGI support.  
This is a merger of execfs and tcp80, both written by cinap_lenrek.

Installation:
-------------
Install with `mk install`  
Create a `/rc/bin/service/tcp80` file:  
```
#!/bin/rc
exec /bin/tcp80x -r /path/to/rules
```

Request handling:
-----------------
`tcp80x` handles request as follows:
1. Parse the request location
2. Try to match the location against defined rules
3. If a rule matches, execute the associated command line (see Rules)
4. If not, look for a matching file in `/usr/web` and serve it

NB:
- Unless `-t` flag is passed to tcp80x, `/usr/web` is bound to `/` before serving static files.
- For scripts to work properly, they need to return a proper HTTP response.

Rules:
-------
The rules file is used to match incoming requests against a regular expression
and if a match is found execute the command associated with the regular expression.
The format is:
```
# Comment
<regex>\t<command line>\n
```
The command line is transformed with regsub(2) meaning that it can contain references
to matches in the regex in the form '\n' where n is a digit. 

Example:
--------
First we create a rule file:
```
/hello/([^'/]+)	/bin/hello '\1'
```

Then, a `hello` script:
```
#!/bin/rc
rfork en
echo 'HTTP/1.1 200'
echo ''
echo 'Hello '^$1
```

We can now browse to `http://server/hello/bob` which should be displaying 'Hello bob'.

Credits:
--------
cinap_lenrek:
- [execfs](https://www.felloff.net/usr/cinap_lenrek/execfs.tgz)
- [tcp80](https://www.felloff.net/usr/cinap_lenrek/tcp80.tgz)

License:
--------
MIT
