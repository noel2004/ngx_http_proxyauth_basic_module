
Install
=======

Install this module from source:

```
$ wget http://nginx.org/download/nginx-1.9.2.tar.gz
$ tar -xzvf nginx-1.9.2.tar.gz
$ cd nginx-1.9.2/
$ patch -p1 < /path/to/ngx_http_proxyauth_basic_module/proxyauth.patch
$ ./configure --add-module=/ngx_http_proxyauth_basic_module
$ make && make install
```
