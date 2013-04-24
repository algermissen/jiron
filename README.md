jiron
=====

A Java implementation of [Iron](https://github.com/hueniverse/iron), a node.js module for encapsulated tokens.

Usage
-----


    import net.jalg.jiron.Jiron;

    String encrypted = Jron.seal("{ \"some\" : \"js\"}", "geheim" , Jiron.Options.DEFAULT);

    String original = Jron.unseal("geheim" , Jiron.Options.DEFAULT);

