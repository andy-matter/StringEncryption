
////////////////////////////////////////////////////////////////////////////////////////////////
//  - Actualy return if encrypt/decrypt passed ore failed
//  - Surch delimiter from back to front of the segment, to allow the delimiter to appear in the data
////////////////////////////////////////////////////////////////////////////////////////////////


#pragma once

class StringEncryption {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  * @param Delimiter: The delimiter between data and salt
  */
  void setup (const uint8_t *Key, char Delimiter);


/** @param InputString: The unencrypted plain text data to be encrypted (MUST NOT CONTAIN '!')
  * @param return: The encrypted data using AES256 encryption and random salt
  */
  bool EncryptString(String &InputString, String &OutputString);


/** @param InputString: The encrypted cypher text data to be decrypted
  * @param return: The decrypted data using AES256 decryption
  */
  bool DecryptString(String &InputString, String &OutputString);

private:

  const uint8_t *AES_Key;
  char DELIMITER;
};