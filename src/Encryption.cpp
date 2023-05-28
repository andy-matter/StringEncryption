#if defined(ARDUINO) && ARDUINO >= 100
#include "Arduino.h"
#else
#include "WProgram.h"
#endif

#include "Crypto_Core/AES.h"
#include "Encryption.h"


AES256 aes256;


void Encryption::splitByteArray(byte* originalArray, int originalLength, int splitLength, byte** splitArrays, int& numArrays) {
  // Calculate the number of split arrays needed
  numArrays = (originalLength + splitLength - 1) / splitLength;

  // Allocate memory for the split arrays
  for (int i = 0; i < numArrays; i++) {
    splitArrays[i] = new byte[splitLength];
  }

  // Split the original array into multiple arrays
  int currentArrayIndex = 0;
  int currentSplitIndex = 0;

  for (int i = 0; i < originalLength; i++) {
    splitArrays[currentArrayIndex][currentSplitIndex] = originalArray[i];
    currentSplitIndex++;

    if (currentSplitIndex >= splitLength) {
      currentArrayIndex++;
      currentSplitIndex = 0;
    }
  }
}


void Encryption::mergeByteArrays(byte** splitArrays, int numArrays, int splitLength, byte* mergedArray) {
  int currentIndex = 0;
  for (int i = 0; i < numArrays; i++) {
    for (int j = 0; j < splitLength; j++) {
      mergedArray[currentIndex] = splitArrays[i][j];
      currentIndex++;
    }
  }
}



String Encryption::removeSalt(const String& input, const String& delimiter) {
  int delimiterIndex = input.indexOf(delimiter);

  if (delimiterIndex != -1) {
    return input.substring(0, delimiterIndex);
  }

  return input;  // Return the entire string if delimiter not found
}


String Encryption::addSalt(String input, const String& delimiter, byte min_quantity, byte quantity) {

  input += delimiter;   // Add delimiter string

  for (int i = 0; i < (min_quantity + quantity); i++) {    // add "quantity" bytes of salt
    uint8_t salt_int = random(0, 255);
    char salt_str = (char)salt_int;

    input += salt_str;
  }

  return input;
}



void Encryption::MultiPassEncrypt (uint8_t *input, uint8_t *output, int passes) {

  byte encryption_buffer[16];

  // first pass
  if (passes > 0) {
    aes256.encryptBlock(encryption_buffer, input);
  }
  else {
    for (int i = 0; i < 16; i++) {
      encryption_buffer[i] = input[i];
    }
  }

  // further passages
  for (int count = 1; count < passes; ++count) {
      aes256.encryptBlock(encryption_buffer, encryption_buffer);
  }

  // Output
  for (int i = 0; i < 16; i++) {
      output[i] = encryption_buffer[i];
  }
}


void Encryption::MultiPassDecrypt (uint8_t *input, uint8_t *output, int passes) {

  byte decryption_buffer[16];

  // first pass
  if (passes > 0) {
    aes256.decryptBlock(decryption_buffer, input);
  }
  else {
    for (int i = 0; i < 16; i++) {
      decryption_buffer[i] = input[i];
    }
  }

  // further passages
  for (int count = 1; count < passes; ++count) {
      aes256.decryptBlock(decryption_buffer, decryption_buffer);
  }

  // Output
  for (int i = 0; i < 16; i++) {
      output[i] = decryption_buffer[i];
  }
}



void Encryption::setSecrets (const uint8_t *Key, const byte Passes) {

  if (Passes <= 3) {
    AES_Passes = Passes;
  }
  else {
    AES_Passes = 3;
  }

  AES_Key = Key;

}


String Encryption::Encrypt(String InputString) {

  String delimiter = "---";
  byte minAddedSalt = 2;  // Add at least 2 bytes of salt

  aes256.setKey(AES_Key, 32);

  // Add salt
  int reminder = (InputString.length() + delimiter.length() + minAddedSalt) % 16;
  int saltToAdd = (16 - reminder);  // add salt up to the next multiple of 16
  String SaltedString = "";

  SaltedString = addSalt(InputString, delimiter, minAddedSalt, saltToAdd);


  // String to Byte-Array
  byte PlaneBytes[SaltedString.length()];
  SaltedString.getBytes(PlaneBytes, SaltedString.length() + 1);


  // Split into byte[16] arrays
  const int originalLength = sizeof(PlaneBytes) / sizeof(PlaneBytes[0]);
  const int splitLength = 16;
  const int maxNumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[maxNumArrays];
  int numArrays = 0;

  splitByteArray(PlaneBytes, originalLength, splitLength, splitArrays, numArrays);


  // Encrypt the byte[16] arrays
  for (int i = 0; i < numArrays; i++) {
    MultiPassEncrypt(splitArrays[i], splitArrays[i], AES_Passes);
  }


  // Merge byte[16] arrays back together
  const int mergedLength = numArrays * splitLength;
  byte mergedArray[mergedLength];

  mergeByteArrays(splitArrays, numArrays, splitLength, mergedArray);


  // Free the memory allocated for split arrays
  for (int i = 0; i < numArrays; i++) {
    delete[] splitArrays[i];
  } 


  // Convert byte-array to String
  String EnctyptedString = "";

  for (int i = 0; i < mergedLength; i++) {
    EnctyptedString += (char)mergedArray[i];
  }

  return EnctyptedString;
}


String Encryption::Decrypt(String InputString)
{

  String delimiter = "---";

  aes256.setKey(AES_Key, 32);

  // String to Byte-Array
  byte PlaneBytes[InputString.length()];
  InputString.getBytes(PlaneBytes, InputString.length() + 1);


  // Split into byte[16] arrays
  const int originalLength = sizeof(PlaneBytes) / sizeof(PlaneBytes[0]);
  const int splitLength = 16;
  const int maxNumArrays = (originalLength + splitLength - 1) / splitLength;
  byte* splitArrays[maxNumArrays];
  int numArrays = 0;

  splitByteArray(PlaneBytes, originalLength, splitLength, splitArrays, numArrays);


  // Decrypt
  for (int i = 0; i < numArrays; i++) {
    MultiPassDecrypt(splitArrays[i], splitArrays[i], AES_Passes);
  }


  // Merge byte[16] arrays back together
  const int mergedLength = numArrays * splitLength;
  byte mergedArray[mergedLength];

  mergeByteArrays(splitArrays, numArrays, splitLength, mergedArray);


  // Free the memory allocated for split arrays
  for (int i = 0; i < numArrays; i++) {
    delete[] splitArrays[i];
  } 


  // Byte-Array to String
  String DectyptedString = "";

  for (int i = 0; i < mergedLength; i++) {
    DectyptedString += (char)mergedArray[i];
  }


  // Remove salt
  DectyptedString = removeSalt(DectyptedString, delimiter);

  return DectyptedString;
}

