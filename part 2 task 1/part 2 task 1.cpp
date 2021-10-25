#include "palisade.h"
#include <iostream>
#include <chrono>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <math.h>
#include <typeinfo>
#include <numeric>

using namespace lbcrypto;
using namespace std;
using namespace std::chrono;

// Function for homomorphic addition. Task 1
void homoAdd(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair);

// Function for homomorphic multipication. Task 2
void homoMul(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair);

// Function for inner product. Task 3
void homoInnerProduct(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair);

// Function for inner product of 1 encrypted vector and 1 normal. Task 4
void semiEncryptedInnerProduct(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair);

int main() {

  cout << "running test1" << endl;

  // Set the main parameters
  int plaintextModulus = 65537;
  double sigma = 3.2;
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;


  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

  // Enable features that we wish to use
  cryptoContext->Enable(ENCRYPTION);
  cryptoContext->Enable(SHE);
  cryptoContext->Enable(LEVELEDSHE);

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> keyPair;

  // Generate a public/private key pair
  keyPair = cryptoContext->KeyGen();

  // Generate the relinearization key
  cryptoContext->EvalMultKeyGen(keyPair.secretKey);
  cryptoContext->EvalSumKeyGen(keyPair.secretKey);
  // Generate the rotation evaluation keys
  cryptoContext->EvalAtIndexKeyGen(keyPair.secretKey, {1, 2, -1, -2});

  // call functions
  cout << "calling functions" << endl;
//  homoMul(cryptoContext, keyPair);
  homoAdd(cryptoContext, keyPair);
  homoInnerProduct(cryptoContext, keyPair);
  semiEncryptedInnerProduct(cryptoContext, keyPair);

  return 0;
}

// Function for homomorphic multipication. Task 2
void homoMul(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair)
{
  ofstream file; // create file object
  file.open("C:\\msys64\\home\\user\\project\\homoMul Times.csv"); // open file
  cout << "running homoMul" << endl;

  for(int n = 1; n <= 11; n++)
  {
    // write to file the size of the vector
    file << "n = " << n << ',';

    // init the vectors using randoms
    vector<int> mulNums;
    vector<Ciphertext<DCRTPoly>> mulVectors;
    for(int i = 0; i < n; i++)
    {
      mulNums.push_back(rand() % 3 + 1);
      cout << mulNums[i] << " ";
      // Encode plaintext
      Plaintext plaintextTmp1 = cryptoContext->MakePackedPlaintext(vector<int64_t>{mulNums[i]});

      // Encrypt plaintext
      auto ciphertextTmp1 = cryptoContext->Encrypt(keyPair.publicKey, plaintextTmp1);

      // push ciphertexts to vector
      mulVectors.push_back(ciphertextTmp1);
    }

    // Calculate real result
    int mulRes = 1;
    for(int i = 0; i < n; i++)
    {
      mulRes *= mulNums[i];
    }

    // Run each test 20 times
    for(int j = 0; j < 20; j++)
    {
      // start timer
      auto start = high_resolution_clock::now();

      // Calculate result after ENCRYPTION
      auto ciphertextMul = cryptoContext->EvalMultMany(mulVectors);

      // stop timer
      auto stop = high_resolution_clock::now();

      // clac time
      auto duration = duration_cast<microseconds>(stop - start);

      // decrypt the vector
      Plaintext plaintextMul;
      cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul, &plaintextMul);

      // get the Mul
      plaintextMul->SetLength(1);
      auto result = plaintextMul->GetPackedValue()[0];

      // Check if there is an error
      if(mulRes - result != 0)
      {
        cout << "error in Mul while n = " << n << endl;
      }

      // Write to file
      file << duration.count() << ',';
    }
    file << '\n';
    cout << "finished n = " << n << endl;
  }
  return;
}

// Function for homomorphic addition. Task 1
void homoAdd(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair)
{
  ofstream file; // create file object
  file.open("C:\\msys64\\home\\user\\project\\homoAdd Times.csv"); // open file
  cout << "running homoAdd" << endl;

  for(int i = 0; i < 11; i++)
  {
    // write to file the size of the vector
    file << "n = " << pow(2, i) << ',';

    // init the vector using random
    vector<int64_t> vectorOfInts1;
    vector<int> timeVector;
    for(int k = 0; k < pow(2, i); k++)
    {
      vectorOfInts1.push_back(rand() % 10 + 1);
    }

    // calculate the sum of the cevtor before ENCRYPTION
    auto realSum = accumulate(vectorOfInts1.begin(), vectorOfInts1.end(), 0);

    // First plaintext vector is encoded
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    for(int j = 0; j < 20; j++)
    {
      // start timer
      auto start = high_resolution_clock::now();

      // sum of vector
      auto ciphertextSum = cryptoContext->EvalSum(ciphertext1, vectorOfInts1.size());

      // stop timer
      auto stop = high_resolution_clock::now();

      // clac time
      auto duration = duration_cast<microseconds>(stop - start);

      // decrypt the vector
      Plaintext plaintextSum;
      cryptoContext->Decrypt(keyPair.secretKey, ciphertextSum, &plaintextSum);

      // get the sum
      plaintextSum->SetLength(1);
      auto result = plaintextSum->GetPackedValue()[0];

      // check if there is an error
      if(realSum - result != 0)
      {
        cout << "error in sum" << endl;
      }

      // write to file
      file << duration.count() << ',';
    }
    file << '\n';
  }
  return;
}

// Function for inner product. Task 3
void homoInnerProduct(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair)
{
  ofstream file; // create file object
  file.open("C:\\msys64\\home\\user\\project\\homoInnerProduct Times.csv"); // open file
  cout << "running homoInnerProduct" << endl;

  for(int i = 0; i < 11; i++)
  {
    // write to file the size of the vector
    file << "n = " << pow(2, i) << ',';

    // init vectors using random and calculate inner product
    vector<int64_t> vectorOfInts1;
    vector<int64_t> vectorOfInts2;
    vector<int> timeVector;
    int product = 0;

    for(int k = 0; k < pow(2, i); k++)
    {
      vectorOfInts1.push_back(rand() % 10 + 1);
      vectorOfInts2.push_back(rand() % 10 + 1);
      product += vectorOfInts1[k] * vectorOfInts2[k];
    }

    // Encode vector as plain text
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    // Encrypt the encoded vectors
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    for(int j = 0; j < 20; j++)
    {
      // start timer
      auto start = high_resolution_clock::now();

      // Calculate inner product
      auto ciphertextInner = cryptoContext->EvalInnerProduct(ciphertext1, ciphertext2, vectorOfInts1.size());

      // stop timer
      auto stop = high_resolution_clock::now();

      // clac time
      auto duration = duration_cast<microseconds>(stop - start);

      // decrypt the vector
      Plaintext plaintextInner;
      cryptoContext->Decrypt(keyPair.secretKey, ciphertextInner, &plaintextInner);

      // get the sum
      plaintextInner->SetLength(1);
      auto result = plaintextInner->GetPackedValue()[0];

      // check if there is an error
      if(product - result != 0)
      {
        cout << "error in inner product" << endl;
      }

      // write to file
      file << duration.count() << ',';
    }
    file << '\n';
  }
  return;
}

// Function for inner product of 1 encrypted vector and 1 normal. Task 4
void semiEncryptedInnerProduct(CryptoContext<DCRTPoly>& cryptoContext, LPKeyPair<DCRTPoly>& keyPair)
{
  ofstream file; // create file object
  file.open("C:\\msys64\\home\\user\\project\\semiEncryptedInnerProduct Times.csv"); // open file
  cout << "running semiEncryptedInnerProduct" << endl;

  for(int i = 0; i < 11; i++)
  {
    // write to file the size of the vector
    file << "n = " << pow(2, i) << ',';

    // init vectors using random and calculate inner product
    vector<int64_t> vectorOfInts1;
    vector<int64_t> vectorOfInts2;
    vector<int> timeVector;
    int product = 0;

    for(int k = 0; k < pow(2, i); k++)
    {
      vectorOfInts1.push_back(rand() % 10 + 1);
      vectorOfInts2.push_back(rand() % 10 + 1);
      product += vectorOfInts1[k] * vectorOfInts2[k];
    }

    // Encode vector as plain text
    Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    Plaintext plaintext2 = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    // Encrypt only one vector
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    for(int j = 0; j < 20; j++)
    {
      // start timer
      auto start = high_resolution_clock::now();

      // Calculate inner product
      auto ciphertextInner = cryptoContext->EvalInnerProduct(ciphertext1, plaintext2, vectorOfInts1.size());

      // stop timer
      auto stop = high_resolution_clock::now();

      // clac time
      auto duration = duration_cast<microseconds>(stop - start);

      // decrypt the vector
      Plaintext plaintextInner;
      cryptoContext->Decrypt(keyPair.secretKey, ciphertextInner, &plaintextInner);

      // get the sum
      plaintextInner->SetLength(1);
      auto result = plaintextInner->GetPackedValue()[0];

      // check if there is an error
      if(product - result != 0)
      {
        cout << "error in inner product" << endl;
      }

      // write to file
      file << duration.count() << ',';
    }
    file << '\n';
  }
  return;
}
