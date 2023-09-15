
#ifndef Encrypt_AES
#define Encrypt_AES


class Encryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  */
  void setSecrets (const uint8_t *Key);


/** @param InputString: The unencrypted plain text data to be encrypted (MUST NOT CONTAIN '!')
  * @param return: The encrypted data using AES256 encryption and random salt
  */
  String EncryptString(String InputString);


/** @param InputString: The encrypted cypher text data to be decrypted
  * @param return: The decrypted data using AES256 decryption
  */
  String DecryptString(String InputString);

private:

  const uint8_t *AES_Key;

  void StringToByteArrays(String inputString, int originalLength, int splitLength, byte** splitArrays);
  String ByteArraysToString(byte** splitArrays, int numArrays, int splitLength);

  String addSalt(String input);
  String removeSalt(String input);

};


#endif