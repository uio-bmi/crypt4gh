module no.elixir.crypt4gh {
    requires blake2b;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires org.apache.commons.cli;
    requires bcrypt;
    requires scrypt;
    requires bkdf;
    requires org.slf4j;
    requires lombok;

    exports no.elixir.crypt4gh.stream;
    exports no.elixir.crypt4gh.pojo;
    exports no.elixir.crypt4gh.util;
}
