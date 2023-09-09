
#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include "Crypto_Core/Crypto.h"
#include "Crypto_Core/AES.h"
//#include "AES_ESP32.h"
#include "Encryption.h"


AES256 aes256;


void Encryption::splitByteArray(byte* originalArray, int originalLength, int splitLength, byte** splitArrays) {

  int numArrays = (originalLength + splitLength - 1) / splitLength; // Calculate the number of target arrays needed
  int sourceIndex = 0;
  int targetIndex = 0;

  while (sourceIndex < originalLength && targetIndex < numArrays) {
    for (int i = 0; i < splitLength; i++) {
      if (sourceIndex < originalLength) {
        splitArrays[targetIndex][i] = originalArray[sourceIndex];
        sourceIndex++;
      }
    }
    targetIndex++;
  }
}


void Encryption::mergeByteArrays(byte** splitArrays, int numArrays, int splitLength, byte* mergedArray) {
  int currentIndex = 0;
  
  for (int i = 0; i < numArrays; i++) {
    for (int j = 0; j < splitLength; j++) {
      mergedArray[currentIndex++] = splitArrays[i][j];
    }
  }
}



String Encryption::removeSalt(String input) {

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


String Encryption::addSalt(String input) {

  const unsigned int MAX_SEGMENT_LENGTH = 13;
  const int SALT_LENGTH = 16 - MAX_SEGMENT_LENGTH;
  const char DELIMITER = '!';

  String output;
  
  // Split the input string into segments
  for (unsigned int i = 0; i < input.length(); i += MAX_SEGMENT_LENGTH) {
    String segment = input.substring(i, min((i + MAX_SEGMENT_LENGTH), input.length()));

    String salt;

    // Add delimiter to segment
    segment += DELIMITER;

    // Add salt to fill the remaining space up to 16 characters
    while (segment.length() < 16) {
      salt = char(random(34, 255)); // Ecxlude everything up to char33 (!)
      segment += salt;
    }

    // Add segment to output
    output += segment;
  }
  
  return output;
}





void Encryption::setSecrets(const uint8_t *Key) {

  AES_Key = Key;

  aes256.setKey(AES_Key, 32);
}


String Encryption::Encrypt(String InputString) {


  // Add salt
  String SaltedString = addSalt(InputString);



  // String to Byte-Array
  byte PlaneBytes[SaltedString.length()];

  for (int i = 0; i < SaltedString.length(); i++) {
    PlaneBytes[i] = (byte)SaltedString.charAt(i);
  }



  // Split into byte[16] arrays
  const int originalLength = sizeof(PlaneBytes) / sizeof(PlaneBytes[0]);
  const int splitLength = 16;
  const int NumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[NumArrays];

  for (int i = 0; i < NumArrays; i++) {    // Allocate memory for target arrays
    splitArrays[i] = new byte[splitLength];
  }

  splitByteArray(PlaneBytes, originalLength, splitLength, splitArrays);



  // Encrypt the byte[16] arrays
  for (int i = 0; i < NumArrays; i++) {
    aes256.encryptBlock(splitArrays[i], splitArrays[i]);
  }



  // Merge byte[16] arrays back together
  const int mergedLength = NumArrays * splitLength;
  byte mergedArray[mergedLength];

  mergeByteArrays(splitArrays, NumArrays, splitLength, mergedArray);



  // Free the memory allocated for split arrays
  for (int i = 0; i < NumArrays; i++) {
    delete[] splitArrays[i];
  } 



  // Convert byte-array to String
  String EnctyptedString = "";

  for (int i = 0; i < mergedLength; i++) {
    EnctyptedString += (char)mergedArray[i];
  }


  return EnctyptedString;
}


String Encryption::Decrypt(String InputString) {


  // String to Byte-Array
  byte CypherBytes[InputString.length()];

  for (int i = 0; i < InputString.length(); i++) {
    CypherBytes[i] = (byte)InputString.charAt(i);
  }



  // Split into byte[16] arrays
  const int originalLength = sizeof(CypherBytes) / sizeof(CypherBytes[0]);
  const int splitLength = 16;
  const int NumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[NumArrays];

  for (int i = 0; i < NumArrays; i++) {    // Allocate memory for target arrays
    splitArrays[i] = new byte[splitLength];
  }

  splitByteArray(CypherBytes, originalLength, splitLength, splitArrays);



  // Decrypt
  for (int i = 0; i < NumArrays; i++) {
    aes256.decryptBlock(splitArrays[i], splitArrays[i]);
  }



  // Merge byte[16] arrays back together
  const int mergedLength = NumArrays * splitLength;
  byte mergedArray[mergedLength];

  mergeByteArrays(splitArrays, NumArrays, splitLength, mergedArray);



  // Free the memory allocated for split arrays
  for (int i = 0; i < NumArrays; i++) {
    delete[] splitArrays[i];
  } 



  // Byte-Array to String
  String SaltedDectyptedString = "";

  for (int i = 0; i < mergedLength; i++) {
    SaltedDectyptedString += (char)mergedArray[i];
  }



  // Remove salt
  String DectyptedString = removeSalt(SaltedDectyptedString);

  return DectyptedString;
}
