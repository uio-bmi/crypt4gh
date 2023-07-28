module no.uio.ifi.crypt4gh {
    requires blake2b;
    requires lombok;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires bcrypt;
    requires scrypt;
    requires bkdf;
    requires commons.cli;

//    exports no.uio.ifi.crypt4gh;
    exports no.uio.ifi.crypt4gh.stream;
    exports no.uio.ifi.crypt4gh.pojo;
    exports no.uio.ifi.crypt4gh.util;
}