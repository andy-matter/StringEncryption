
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include "Crypto_Core/Crypto.h"
#include "Crypto_Core/AES.h"

#include "StringEncryption.h"

AES256 aes256;




void StringEncryption::setup(const uint8_t *Key) { 

  AES_Key = Key;
  aes256.setKey(AES_Key, 256);
}




bool StringEncryption::EncryptString(String &InputString, String &OutputString) {

  const unsigned int MAX_SEGMENT_LENGTH = 13;  // 13 charaters from original String + delimiter + salt

  OutputString = "";
  

  // Split input into segments, add salt, encrypt and add to output String 
  for (unsigned int i = 0; i < InputString.length(); i += MAX_SEGMENT_LENGTH) {

    // Get segment of input string
    String string_segment = InputString.substring(i, min((i + MAX_SEGMENT_LENGTH), InputString.length()));

    addSalt:

    // Add segment to string
    String String16 = string_segment;

    // Add delimiter to string
    String16 += DELIMITER;

    // Add salt to fill the remaining space up to 16 characters
    char salt;
    while (String16.length() < 16) {
      salt = char(random(1, 255));
      if (salt != DELIMITER) {  // Only add the salt when it's not the delimiter
        String16 += salt;
      }
    }

    // Convert to byte array
    uint8_t Byte16[16];
    for (int j = 0; j < 16; j++) {    
      Byte16[j] = (uint8_t)String16.charAt(j);
    }

    // Encrypt
    aes256.encryptBlock(Byte16, Byte16);

    // Check for NULL bytes (else redo salt)
    for (int j = 0; j < 16; j++) {
      if (Byte16[j] == 0) {
        goto addSalt;
      }
    }

    // Convert back to String
    String String16_output = "";
    for (int j = 0; j < 16; j++) {
      String16_output += (char)Byte16[j];
    }

    // Add string to output
    OutputString += String16_output;
  }
  
  return true;
}




bool StringEncryption::DecryptString(String &InputString, String &OutputString) {

  const unsigned int SEGMENT_LENGTH = 16;

  OutputString = "";
  
  // Split the input string into segments
  for (unsigned int i = 0; i < InputString.length(); i += SEGMENT_LENGTH) {

    // Get segment of input string
    String String16 = InputString.substring(i, (i + SEGMENT_LENGTH));


    // Convert to byte array
    uint8_t Byte16[16];
    for (int j = 0; j < 16; j++) {    
      Byte16[j] = (uint8_t)String16.charAt(j);
    }

    // Encrypt
    aes256.decryptBlock(Byte16, Byte16);

    // Convert back to String
    String out_segment = "";
    for (int j = 0; j < 16; j++) {
      out_segment += (char)Byte16[j];
    }


    // Remove the salt at the delimiter
    // First look an index 13 if not at 13 decrement search
    int delimiterIndex = 13;
    if (out_segment[delimiterIndex] != DELIMITER) {
      
      for (int i = delimiterIndex; i >= 0; i--) {
        if (out_segment[i] == DELIMITER) {
          delimiterIndex = i;
          break;
        }
      }
    }


    OutputString += out_segment.substring(0, delimiterIndex);;
  }

  return true;
}
