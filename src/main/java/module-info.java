module no.uio.ifi.crypt4gh {
    requires blake2b;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires bcrypt;
    requires scrypt;
    requires bkdf;
    requires commons.cli;
    requires org.slf4j;
    requires lombok;

    exports no.uio.ifi.crypt4gh.stream;
    exports no.uio.ifi.crypt4gh.pojo;
    exports no.uio.ifi.crypt4gh.pojo.header;
    exports no.uio.ifi.crypt4gh.pojo.body;
    exports no.uio.ifi.crypt4gh.pojo.key;
    exports no.uio.ifi.crypt4gh.util;
}