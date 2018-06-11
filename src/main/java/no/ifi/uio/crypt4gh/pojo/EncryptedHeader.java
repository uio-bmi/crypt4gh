package no.ifi.uio.crypt4gh.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.ToString;

import java.util.List;

@ToString
@AllArgsConstructor
@Data
public class EncryptedHeader {

    private final long numberOfRecords;
    private final List<Record> records;

}
