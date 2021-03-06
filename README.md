# crypt4gh
[![Build Status](https://github.com/uio-bmi/crypt4gh/workflows/Java%20CI/badge.svg)](https://github.com/uio-bmi/crypt4gh/actions)
[![Dependabot Status](https://api.dependabot.com/badges/status?host=github&repo=uio-bmi/crypt4gh)](https://dependabot.com)
[![CodeFactor](https://www.codefactor.io/repository/github/uio-bmi/crypt4gh/badge/master)](https://www.codefactor.io/repository/github/uio-bmi/crypt4gh/overview/master)
[![Download](https://api.bintray.com/packages/uio-bmi/Crypt4GH/Crypt4GH/images/download.svg)](https://bintray.com/uio-bmi/Crypt4GH/Crypt4GH/_latestVersion)
## Overview
![](https://www.ga4gh.org/wp-content/uploads/Crypt4GH_comic.png)

## File structure
![](https://habrastorage.org/webt/yn/y2/pk/yny2pkp68sccx1vbvmodz-hfpzm.png)

## Specification
Current version of specs can be found [here](http://samtools.github.io/hts-specs/crypt4gh.pdf).

## Maven Installation
To include this library to your Maven project add following to the `pom.xml`:

```xml

...

    <dependencies>
        <dependency>
            <groupId>no.uio.ifi</groupId>
            <artifactId>crypt4gh</artifactId>
            <version>VERSION</version>
        </dependency>
    </dependencies>

...

    <repositories>
        <repository>
            <id>central</id>
            <name>bintray</name>
            <url>https://jcenter.bintray.com</url>
        </repository>
    </repositories>

...

```

## Console Installation
To install console app you can use the following script (assuming you are using `bash`):
```
PREFIX=/usr/local/bin && \
sudo curl -L "https://github.com/uio-bmi/crypt4gh/releases/download/v2.4.1/crypt4gh.jar" -o "$PREFIX/crypt4gh.jar" && \
echo -e '#!/usr/bin/env bash\njava -jar' "$PREFIX/crypt4gh.jar" '$@' | sudo tee "$PREFIX/crypt4gh" > /dev/null && \
sudo chmod +x "$PREFIX/crypt4gh"
```

## Usage
```
$ crypt4gh 
usage: crypt4gh [-d <arg> | -e <arg> | -g <arg> | -h | -v]    [-kf <arg>]
       [-kp <arg>] [-pk <arg>] [-sk <arg>]

Crypt4GH encryption/decryption tool

 -d,--decrypt <arg>    decrypt the file (specify file to decrypt)
 -e,--encrypt <arg>    encrypt the file (specify file to encrypt)
 -g,--generate <arg>   generate key pair (specify desired key name)
 -h,--help             print this message
 -kf,--keyform <arg>   key format to use for generated keys (OpenSSL or
                       Crypt4GH)
 -kp,--keypass <arg>   password for Crypt4GH private key (will be prompted
                       afterwords if skipped)
 -pk,--pubkey <arg>    public key to use (specify key file)
 -sk,--seckey <arg>    secret key to use (specify key file)
 -v,--version          print application's version

Read more about the format at
http://samtools.github.io/hts-specs/crypt4gh.pdf
```
