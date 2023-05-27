
#ifndef Encrypt
#define Encrypt


class Encryption {
public:

  String Encrypt(String InputString, const uint8_t *Key, int Passes);
  String Decrypt(String InputString, const uint8_t *Key, int Passes);

private:

  int used_mqtt_send_variables = 0;
  int used_mqtt_receive_variables = 0;

  void splitByteArray(byte* originalArray, int originalLength, int splitLength, byte** splitArrays, int& numArrays);
  void mergeByteArrays(byte** splitArrays, int numArrays, int splitLength, byte* mergedArray);

  String addSalt(String input, const String& delimiter, byte quantity);
  String removeSalt(const String& input, const String& delimiter);

  void MultiPassEncrypt (uint8_t *input, uint8_t *output, int passes);
  void MultiPassDecrypt (uint8_t *input, uint8_t *output, int passes);

};


#endif