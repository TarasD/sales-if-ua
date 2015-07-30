# REST-Domains-examples



### must to be installed next things:
***************************************************

1. java SE 1.8.

2. apache-maven-3.2.5.

3. MySql Server 5.5 (Linux command: sudo apt-get install mysql-server-5.5)

### Database steps:
***************************************************

1. Create user "salesifua" with password "salesifua"
   ubuntu command - create user "salesifua"@"localhost" identified by "salesifua";
   grant all on . to "salesifua"@"localhost";
   
   mysql -u salesifua -p
   
   CREATE DATABASE salesifua;


### Run server 
***************************************************

1. From console go to project directory
 
2. Enter command mvn jetty:run

Links for using:
### Links to rest controller that's using hibernate
***************************************************
#Links for goods:

1. http://localhost:8080/Practice/goods/ method = GET -- get good list 

2. http://localhost:8080/Practice/goods?id= method = GET -- get good by id

3. http://localhost:8080/Practice/goods method = POST -- save or update good

4. http://localhost:8080/Practice/goods method = DELETE -- delete good

5. http://localhost:8080/Practice/goods/page?page=&amount= and Map into request body like "{"name":"asc"}"
method = POST -- pagination with sorting

8. http://localhost:8080/Practice/goods/search?name= method = GET -- search good by 
  name with ignore case

9. http://localhost:8080/Practice/goods/filter?from=&to= method = GET -- search any good which
  are in scope from and to

#Links for shops:

1. http://localhost:8080/Practice/shops/all?page=&amount=  method = Get -- get shop list
2. http://localhost:8080/Practice/shops/{id}  method = Get -- get shop by id
3. http://localhost:8080/Practice/shops/add  method = Post -- save shop
4. http://localhost:8080/Practice/shops/update/{id}  method = Patch -- update shop
5. http://localhost:8080/Practice/shops/delete/{id}  method = Delete -- delete shop
6. http://localhost:8080/Practice/shops/sort/{field}?page=&amount=  method = Get -- sort shops by 'field'
7. http://localhost:8080/Practice/shops/filter/{field}={value}  method = Get -- filter shops by 'field' equals 'value'
8. http://localhost:8080/Practice/shops/search/{name}  method = Get -- find shop by name

#Links for using: [CLIENTS]

1. http://localhost:8080/Practice/client/{id} method = GET - get Client by id
2. http://localhost:8080/Practice/client/all method = GET - get list of all Clients
3. http://localhost:8080/Practice/client/add method = POST - save Client (comsumes client json)
4. http://localhost:8080/Practice/client/update method = PUT - update Client (consumes client json to be updated)
5. http://localhost:8080/Practice/client/remove/{id} method = DELETE - delete client by id
6. http://localhost:8080/Practice/client/search?name=%name%&surname=%surname%
   method = GET - get Client with name=%name% and surname=%surname%
7. http://localhost:8080/Practice/client/page?page=%page%&amount=%amount%
   method = GET - get client list on page=%page% and with %amount% clients on page

#Links for using: [COMMENTS]

1. http://localhost:8080/Practice/comment/add method = POST - save Comment
2. http://localhost:8080/Practice/comment/all?goodId=%goodId% method = GET - get all comments
   to Good with goodId = %goodId%
3. http://localhost:8080/Practice/comment/remove?commentId=%commentId% method = DELETE -
   remove Comment with commentId = %commentId%


#Links for site pages:
1. http://localhost:8080/Practice/#/home  - Main Page
2. http://localhost:8080/Practice/#/stuff - List of Products
3. http://localhost:8080/Practice/#/character - Characteristic of chosen product
4. http://localhost:8080/Practice/#/user/backet - User's cart (User links on the sidebar)
5. http://localhost:8080/Practice/#/admin/users - Admin's Page (Admin links on the sidebar)

#Install Node.js
Node is a requirement for bower package manager.
You can download a Node.js installer for your operating system from http://nodejs.org/download/.
Check the version of Node.js that you have installed by running the following command in console:
```sh
 node --version
```

#Install Bower
Bower is used for bootstrapping application with needed libraries like Angular.js, jQuery etc.
```sh
 npm install -g bower
```

#Browse required libraries
In your console go to the {system path}/sales-if-ua/src/main/webapp/app and type following comand:
```sh
 bower install
```