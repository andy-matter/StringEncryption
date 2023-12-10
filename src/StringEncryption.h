
#ifndef Encrypt_AES
#define Encrypt_AES


class StringEncryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  * @param Delimiter: The delimiter between data and salt
  */
  void setup (const uint8_t *Key, char Delimiter);


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
  char DELIMITER;

};


#endif