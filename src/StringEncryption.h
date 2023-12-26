
////////////////////////////////////////////////////////////////////////////////////////////////
//  - Actualy return if encrypt/decrypt passed ore failed
////////////////////////////////////////////////////////////////////////////////////////////////


#pragma once

class StringEncryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  */
  void setup (const uint8_t *Key);


/** @param InputString: The unencrypted plain text data to be encrypted (MUST NOT CONTAIN '!')
  * @param OutputString: The encrypted data using AES256 encryption and random salt
  * @param return: True if encryption was successful otherwhise False
  */
  bool EncryptString(String &InputString, String &OutputString);


/** @param InputString: The encrypted cypher text data to be decrypted
  * @param OutputString: The decrypted data using AES256 decryption
  * @param return: True if decryption was successful otherwhise False
  */
  bool DecryptString(String &InputString, String &OutputString);

private:

  const uint8_t *AES_Key;
  const char DELIMITER = '*';
};