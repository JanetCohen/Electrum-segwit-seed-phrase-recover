# Electrum-segwit-seed-phrase-recover
Electrum seed recovery missing last 2 word And the known zpub.

example zpub
zpub6nHN3pRoqoT6KRYYADcbYjdU3DS11MhdB47YZSNYe7Cs3L2M1oQMAxK5dUM1wh4egV54b5JX9RpcAAYTVNaPDgyJ2JwAPTxkXcRMfwmYL1t

you have to decode it first using base58 check then the result is:

04b2474601635013dd800000003e31dbfb10891b28eef72e829ce9e29473fc440f50cd5780cee6b83224b8a40602e327d3ead756b01669f8513bd0c5bff4d46e1e758a56796b9a5dbc89ab805598

then separate it like this

04b2474601
635013dd <==== bip32 root fingerprint 
80000000
3e31dbfb10891b28eef72e829ce9e29473fc440f50cd5780cee6b83224b8a406
02e327d3ead756b01669f8513bd0c5bff4d46e1e758a56796b9a5dbc89ab805598


save that bip32 fingerprint then add it to the code for the target
