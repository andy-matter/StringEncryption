
#include <Arduino.h>
#include <StringEncryption.h>


StringEncryption_ChaCha Cypher;   // Preferred due to higher performance, less overhead and just a better implementation
//StringEncryption_AES Cypher;    // Implemented as stitched together salted data-blocks (AES-ECB)  (instead of AES-CTR)

byte Key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

String TestString = "This is a test-string, here are some character for testing: Test123!§$%/*_#;)";
String EncryptedStr, DecryptedStr;




void setup() {

  Serial.begin(115200);
  delay(100);

  Cypher.setup(Key, 32);   // Setting up the cypher
}




void loop() {

  Cypher.EncryptString(TestString, EncryptedStr, TestString.length());       // Encrypt TestString to EncryptedStr

  Cypher.DecryptString(EncryptedStr, DecryptedStr, EncryptedStr.length());   // Decrypt EncryptedStr to DecryptedStr


  if (!TestString.equals(DecryptedStr)) {    // Compare TestString and DecryptedStr
    Serial.println("Test Failed");
  }

  while(1);   // Freeze the loop
}