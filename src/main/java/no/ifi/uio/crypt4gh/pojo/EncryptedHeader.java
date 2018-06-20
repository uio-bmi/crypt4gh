package no.ifi.uio.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

import java.util.List;

/**
 * Encrypted Crypt4GH header POJO.
 */
@ToString
@AllArgsConstructor
@Data
public class EncryptedHeader {

    private final long numberOfRecords;
    private final List<Record> records;

}
