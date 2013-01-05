Installation
------------

```
make install
```

to build without SSL support:
```
make -f Makefile.nossl install
```

To get TCP TFO Support  - Compile Using
```
TFO=yes make all
```

On *BSD compile using `gmake`.


Usage
-----

* Basic:
```
httping www.vanheusden.com
```

* Multihost:
```
httping badnack.it http://nebirhos.com:12345
```


Credits
-------

Thanks to Thanatos for cookie and authentication support.

TCP TFO support is added by Ketan Kulkarni. Please report any issues at ketkulka@gmail.com.

Multihost support by Nilo Redini, Francesco Disperati, Davide Pellegrino.

For everything more or less related to 'httping', please feel free
to contact me on: folkert@vanheusden.com
Consider using PGP. My PGP key-id is: 0x1f28d8ae

Please support my opensource development: http://www.vanheusden.com/wishlist.php
