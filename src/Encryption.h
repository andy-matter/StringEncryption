
#ifndef Encrypt_AES
#define Encrypt_AES


class Encryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  */
  void setSecrets (const uint8_t *Key);


/** @param InputString: The unencryptet plain text data to be encrypted
  * @param return: The encrypted data using multiple AES256 encryption-cycles and random salt
  */
  String Encrypt(String InputString/*, const uint8_t *Key, int Passes*/);


/** @param InputString: The encryptet cypher text data to be decrypted
  * @param return: The decrypted data using multiple AES256 decryption-cycles
  */
  String Decrypt(String InputString/*, const uint8_t *Key, int Passes*/);

private:

  const uint8_t *AES_Key;

  void splitByteArray(byte* originalArray, int originalLength, int splitLength, byte** splitArrays);
  void mergeByteArrays(byte** splitArrays, int numArrays, int splitLength, byte* mergedArray);

  String addSalt(String input);
  String removeSalt(String input);

};


#endif