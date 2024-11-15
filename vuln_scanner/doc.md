Following https://avleonov.com/2022/10/04/how-to-perform-a-free-ubuntu-vulnerability-scan-with-openscap-and-canonicals-official-oval-content/


### Process

First we grab the OVAL data at https://security-metadata.canonical.com/oval/com.ubuntu.<release>.usn.oval.xml.bz2


We install `oscap-scanner` and use the ubuntu OVAL document

wget https://security-metadata.canonical.com/oval/com.ubuntu.$(lsb_release -cs).usn.oval.xml.bz2