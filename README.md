jiron
=====

A Java implementation of [Iron](https://github.com/hueniverse/iron), a node.js module for encapsulated tokens. 

Please refer to the README of iron for documentation. Especially, read the [security considerations](https://github.com/hueniverse/iron#security-considerations)
before using this library.

Status
------

I have moved jiron to 1.0. If you plan
to use this in production do it with some caution as there has not yet been much production
feedback.

Personally, I use [jiron for cookie authentication](https://github.com/algermissen/iron-cookie)
 in a JAX-RS 2 project without problems.


How to get it?
--------------

Maven dependency:


    <dependency>
      <groupId>net.jalg</groupId>
      <artifactId>jiron</artifactId>
      <version>1.0</version>
    </dependency>



Usage
-----


    import net.jalg.jiron.Jiron;

    String encrypted = Jiron.seal("This is a secret message.", "secret" , Jiron.DEFAULT_ENCRYPTION_OPTIONS, Jiron.DEFAULT_INTEGRITY_OPTIONS);

    String original = Jiron.unseal(encrypted, "secret" , Jiron.DEFAULT_ENCRYPTION_OPTIONS, Jiron.DEFAULT_INTEGRITY_OPTIONS);

256bit AES Keys and Unlimited Strength Jurisdiction Policy Files
----------------------------------------------------------------
Jiron default options use 256bit AES keys. In order to use this key length you need to install the
_Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files_. You can download
them from the Oracle Technetwork
[download page](http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters/6481658#6481658)
 (scroll down to _Additional Resources_) and follow the instructions in the README after unzipping.

See also [http://www.ngs.ac.uk/tools/jcepolicyfiles](http://www.ngs.ac.uk/tools/jcepolicyfiles).

An alternative is to include the following code in your program, as described in (http://suhothayan.blogspot.de/2012/05/how-to-install-java-cryptography.html)

~~~

  try { 
    Field field = Class.forName("javax.crypto.JceSecurity").
    getDeclaredField("isRestricted");
    field.setAccessible(true);
    field.set(null, java.lang.Boolean.FALSE); 
  } catch (Exception ex) {
    ex.printStackTrace();
  }

~~~



