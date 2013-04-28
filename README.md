jiron
=====

A Java implementation of [Iron](https://github.com/hueniverse/iron), a node.js module for encapsulated tokens. 

Please refer to the README of iron for documentation. Especially, read the [security considerations](https://github.com/hueniverse/iron#security-considerations)
before using this libary.




Usage
-----


    import net.jalg.jiron.Jiron;

    String encrypted = Jron.seal("This is a secret message.", "secret" , Jiron.Options.DEFAULT);

    String original = Jron.unseal("secret" , Jiron.Options.DEFAULT);

256bit AES Keys and Unlimited Strength Jurisdiction Policy Files
----------------------------------------------------------------
Jiron default options use 256bit AES keys. In order to use this key length you need to install the
_Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files_. You can download
them from the Oracle Technetwork
[download page](http://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters/6481658#6481658)
 (scroll down to _Additional Resources_) and follow the instructions in the README after unzipping.

See also [http://www.ngs.ac.uk/tools/jcepolicyfiles](http://www.ngs.ac.uk/tools/jcepolicyfiles).

An alternative is to include the following code in your program, as described in [http://suhothayan.blogspot.de/2012/05/how-to-install-java-cryptography.html]

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

