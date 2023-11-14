module no.uio.ifi.crypt4gh {
    requires com.rfksystems.blake2b;
    requires org.apache.commons.lang3;
    requires org.apache.commons.io;
    requires org.apache.commons.cli;
    requires bcrypt;
    requires scrypt;
    requires bkdf;
    requires org.slf4j;
    requires lombok;

    exports no.uio.ifi.crypt4gh.stream;
    exports no.uio.ifi.crypt4gh.pojo;
    exports no.uio.ifi.crypt4gh.util;
}
