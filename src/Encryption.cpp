
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include "Crypto_Core/Crypto.h"
#include "Crypto_Core/AES.h"
//#include "AES_ESP32.h"

#include "Encryption.h"


//AES_ESP32 aes256;
AES256 aes256;




void StringEncryption::StringToByteArrays(String inputString, int originalLength, int splitLength, byte** splitArrays) {

  int numArrays = (originalLength + splitLength - 1) / splitLength; // Calculate the number of target arrays needed
  int sourceIndex = 0;
  int targetIndex = 0;

  byte inputBytes[originalLength];

  for (int i = 0; i < originalLength; i++) {
    inputBytes[i] = (byte)inputString.charAt(i);
  }

  while (sourceIndex < originalLength && targetIndex < numArrays) {
    for (int i = 0; i < splitLength; i++) {
      if (sourceIndex < originalLength) {
        splitArrays[targetIndex][i] = inputBytes[sourceIndex];
        sourceIndex++;
      }
    }
    targetIndex++;
  }
}




String StringEncryption::ByteArraysToString(byte** splitArrays, int numArrays, int splitLength) {
  
  int outputLength = numArrays * splitLength;
  String outputString = "";

  int currentIndex = 0;
  byte mergedArray[outputLength];

  
  for (int i = 0; i < numArrays; i++) {
    for (int j = 0; j < splitLength; j++) {
      mergedArray[currentIndex++] = splitArrays[i][j];
    }
  }


  for (int i = 0; i < outputLength; i++) {
    outputString += (char)mergedArray[i];
  }

  return outputString;
}




String StringEncryption::removeSalt(String input) {

  const unsigned int SEGMENT_LENGTH = 16;
  const char DELIMITER = '!';

  String output = "";
  
  // Split the input string into segments
  for (unsigned int i = 0; i < input.length(); i += SEGMENT_LENGTH) {

    String segment = input.substring(i, (i + SEGMENT_LENGTH));

    int delimiterIndex = segment.indexOf(DELIMITER);

    if (delimiterIndex != -1) {
      segment = segment.substring(0, delimiterIndex);
    }

    output += segment;
  }

  return output;
}




String StringEncryption::addSalt(String input) {

  const unsigned int MAX_SEGMENT_LENGTH = 13;
  const int SALT_LENGTH = 16 - MAX_SEGMENT_LENGTH;
  const char DELIMITER = '!';

  String output;
  

  for (unsigned int i = 0; i < input.length(); i += MAX_SEGMENT_LENGTH) {

    // Get segment of input string
    String segment = input.substring(i, min((i + MAX_SEGMENT_LENGTH), input.length()));

    // Add delimiter to segment
    segment += DELIMITER;

    // Add salt to fill the remaining space up to 16 characters
    String salt = "";
    while (segment.length() < 16) {
      salt = char(random(34, 255)); // Ecxlude everything up to char33 (!)
      segment += salt;
    }

    // Add segment to output
    output += segment;
  }
  

  return output;
}






void StringEncryption::setSecrets(const uint8_t *Key) {

  AES_Key = Key;

  aes256.setKey(AES_Key, 256);
}




String StringEncryption::EncryptString(String InputString) {

  // Add salt
  String SaltedString = addSalt(InputString);


  // String to byte[16] arrays
  const int originalLength = SaltedString.length();
  const int splitLength = 16;
  const int NumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[NumArrays];

  for (int i = 0; i < NumArrays; i++) {    // Allocate memory for target arrays
    splitArrays[i] = new byte[splitLength];
  }

  StringToByteArrays(SaltedString, originalLength, splitLength, splitArrays);


  // Encrypt the byte[16] arrays
  for (int i = 0; i < NumArrays; i++) {
    aes256.encryptBlock(splitArrays[i], splitArrays[i]);
  }


  // Merge byte[16] arrays back together
  String EnctyptedString = ByteArraysToString(splitArrays, NumArrays, splitLength);


  // Free the memory allocated for split arrays
  for (int i = 0; i < NumArrays; i++) {
    delete[] splitArrays[i];
  } 


  return EnctyptedString;
}




String StringEncryption::DecryptString(String InputString) {

  // String to byte[16] arrays
  const int originalLength = InputString.length();
  const int splitLength = 16;
  const int NumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[NumArrays];

  for (int i = 0; i < NumArrays; i++) {    // Allocate memory for target arrays
    splitArrays[i] = new byte[splitLength];
  }

  StringToByteArrays(InputString, originalLength, splitLength, splitArrays);


  // Decrypt the byte[16] arrays
  for (int i = 0; i < NumArrays; i++) {
    aes256.decryptBlock(splitArrays[i], splitArrays[i]);
  }


  // Merge byte[16] arrays back together
  String SaltedDectyptedString = ByteArraysToString(splitArrays, NumArrays, splitLength);


  // Free the memory allocated for split arrays
  for (int i = 0; i < NumArrays; i++) {
    delete[] splitArrays[i];
  } 


  // Remove salt
  String DectyptedString = removeSalt(SaltedDectyptedString);


  return DectyptedString;
}
