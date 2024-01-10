
////////////////////////////////////////////////////////////////////////////////////////////////
//  - Actualy return if encrypt/decrypt passed ore failed
////////////////////////////////////////////////////////////////////////////////////////////////


#pragma once


#include "CryptoCore/AES.h"
#include "CryptoCore/ChaCha.h"



class StringEncryption_AES {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  */
  void setup (const uint8_t *Key, uint8_t keyLength);


/** @param InputString: The unencrypted plain text data to be encrypted (MUST NOT CONTAIN '!')
  * @param OutputString: The encrypted data using AES256 encryption and random salt
  * @param return: True if encryption was successful otherwhise False
  */
  bool EncryptString(String &InputString, String &OutputString, short length);


/** @param InputString: The encrypted cypher text data to be decrypted
  * @param OutputString: The decrypted data using AES256 decryption
  * @param return: True if decryption was successful otherwhise False
  */
  bool DecryptString(String &InputString, String &OutputString, short length);

private:

  AES256 aes256;
  const char DELIMITER = '*';
};






class StringEncryption_ChaCha {
public:

/** @param Key: The AES256 encryption-key as a Byte[32] array
  */
  void setup (const uint8_t *Key, uint8_t keyLength);


/** @param InputString: The unencrypted plain text data to be encrypted (MUST NOT CONTAIN '!')
  * @param OutputString: The encrypted data using AES256 encryption and random salt
  * @param return: True if encryption was successful otherwhise False
  */
  bool EncryptString(String &InputString, String &OutputString, short length);


/** @param InputString: The encrypted cypher text data to be decrypted
  * @param OutputString: The decrypted data using AES256 decryption
  * @param return: True if decryption was successful otherwhise False
  */
  bool DecryptString(String &InputString, String &OutputString, short length);


  private:

  ChaCha chacha = ChaCha(12);
  const uint8_t ChaChaCounter[8] = {0xBE, 0xC9, 0x3F, 0xA6, 0x52, 0xDA, 0x4E, 0x7D}; 
};