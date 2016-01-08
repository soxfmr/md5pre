# md5pre
MD5 Hash Query Online And Generator

# What's md5pre
**md5pre** is a tool which can query the plain text of a MD5 hash using the API supply by the online MD5 cracking website. You can load the hashes from local file, or to type-hint directly. And it can used to generate the MD5 hashes as well.

![md5pre](http://i.imgur.com/JdQK2VI.png)

# Query the plain text of the MD5 hash
The argument **-q** (query) Implies that perform the query action, **-r** (raw) specify a MD5 hash[es] instead the local file
```
python md5pre.py -q -r 21232f297a57a5a743894a0e4a801fc3
```
![lucky](http://i.imgur.com/nhe88n5.png)

You can also query the MD5 hash from the local file, the result of the query will be stored in **plain_*** file :
```
python md5pre.py -q -i hash.txt
```
![cracking-input-file](http://i.imgur.com/XHLRhgR.png)

# Generate the MD5 Hash
```
python md5pre.py -c -r admin
```
Generate the MD5 hashes of the plain text that read from local file:
```
python md5pre.py -c -i plain.txt
```
