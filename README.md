# signature-escrow.

The signature-escrow repository allows you to exchange tokens using multi-signatures (they are based on MPC technology or multi-party computing). For more information, see the docs.

1. To create shared keys, you need a message broker. For now, redis is supported, but later it will have its own server.
  The command to get the redis image: 
  ``` docker pull redis ```.
  The command to start the redis container:
   ``` docker run --name my-redis -p 6379:6379 -d redis ```.
  The config/config.yml file contains an example config. The Network field specifies the address and port of the message broker

  ---

  Alice's command: ```go run main.go keygen --config config/config.yml --pass hello --alg ecdsa --name alice```
  Bob's: ``` go run main.go keygen --config config/config.yml --pass hello --alg ecdsa --name bob ```
 
  **keygen** - command to create shared keys command to create shared keys, **config** - flag for specifying the location of the config, **pass** - the password that will encrypt the private parts for signing(AES), **alg** - signature algorithm, ECDSA or FROST(improved Schnorr), **name** - specify the directory for the key data, it is possible to store several shared keys in the same directory