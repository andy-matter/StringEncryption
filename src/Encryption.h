
#ifndef Encrypt_AES
#define Encrypt_AES


class Encryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  * @param Passes: The number of encryption passes, between 0 and 5
  */
  void setSecrets (const uint8_t *Key, const byte Passes);


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
  int AES_Passes;

  void splitByteArray(byte* originalArray, int originalLength, int splitLength, byte** splitArrays, int& numArrays);
  void mergeByteArrays(byte** splitArrays, int numArrays, int splitLength, byte* mergedArray);

  String addSalt(String input, const String& delimiter, byte min_quantity, byte quantity);
  String removeSalt(const String& input, const String& delimiter);

  void MultiPassEncrypt (uint8_t *input, uint8_t *output, int passes);
  void MultiPassDecrypt (uint8_t *input, uint8_t *output, int passes);

};


#endif