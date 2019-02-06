# crypt4gh
[![Build Status](https://travis-ci.org/uio-bmi/crypt4gh.svg?branch=master)](https://travis-ci.org/uio-bmi/crypt4gh)
## Overview
![](https://habrastorage.org/webt/mz/7a/wa/mz7awalkt13exw7sgtdh9eexv3q.png)

## Specification
Current version of specs can be found [here](https://hyperbrowser.uio.no/hb/static/hyperbrowser/files/crypt4gh/crypt4gh.pdf).

## Maven Installation
To include this library to your Maven project add following to the `pom.xml`:

```xml

...

    <dependencies>
        <dependency>
            <groupId>no.uio.ifi</groupId>
            <artifactId>crypt4gh</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>

    <repositories>
        <repository>
            <id>nexus.norgene.no</id>
            <url>https://nexus.norgene.no/repository/maven-releases/</url>
        </repository>
    </repositories>

...

```

## Console Installation
To install console app you can use the following script (assuming you are using `bash`):
```
PREFIX=/usr/local/bin && \
sudo curl -L "https://github.com/uio-bmi/crypt4gh/releases/download/v1.2.0/crypt4gh-1.2.0-shaded.jar" -o "$PREFIX/crypt4gh.jar" && \
echo -e '#!/usr/bin/env bash\njava -jar' "$PREFIX/crypt4gh.jar" '$@' | sudo tee "$PREFIX/crypt4gh" > /dev/null && \
sudo chmod +x "$PREFIX/crypt4gh"
```

## Usage
```
$ crypt4gh 
usage: crypt4gh [-d <arg> | -e <arg> | -g <arg> | -h]    [-k <arg>] [-v]

Crypt4GH encryption/decryption tool

 -d,--decrypt <arg>    decrypt the file (specify filename/filepath)
 -e,--encrypt <arg>    encrypt the file (specify filename/filepath)
 -g,--generate <arg>   generate PGP keypair (specify key ID)
 -h,--help             print this message
 -k,--key <arg>        PGP key to use
 -v,--verbose          verbose mode

Read more about the format at http://bit.ly/crypt4gh
```
