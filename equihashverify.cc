#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"

#include <vector>

// No need for 'using namespace v8;' when using Nan

int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, unsigned int n = 200, unsigned int k = 9){
  // Hash state
  crypto_generichash_blake2b_state state;
  EhInitialiseState(n, k, state);

  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

  bool isValid;
  if (n == 96 && k == 3) {
      isValid = Eh96_3.IsValidSolution(state, soln);
  } else if (n == 200 && k == 9) {
      isValid = Eh200_9.IsValidSolution(state, soln);
  } else if (n == 144 && k == 5) {
      isValid = Eh144_5.IsValidSolution(state, soln);
  } else if (n == 192 && k == 7) {
      isValid = Eh192_7.IsValidSolution(state, soln);
  } else if (n == 96 && k == 5) {
      isValid = Eh96_5.IsValidSolution(state, soln);
  } else if (n == 48 && k == 5) {
      isValid = Eh48_5.IsValidSolution(state, soln);
  } else {
      throw std::invalid_argument("Unsupported Equihash parameters");
  }
  
  return isValid;
}

void Verify(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  unsigned int n = 200;
  unsigned int k = 9;

    // Check the number of arguments
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Wrong number of arguments");
  return;
  }

    // Convert the first two arguments to v8::Object
    v8::Local<v8::Object> header;
    v8::Local<v8::Object> solution;

    if (!info[0]->IsObject() || !info[1]->IsObject()) {
        Nan::ThrowTypeError("Arguments should be buffer objects.");
        return;
  }

    header = info[0]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();
    solution = info[1]->ToObject(Nan::GetCurrentContext()).ToLocalChecked();

    // If there are four arguments, parse 'n' and 'k'
    if (info.Length() == 4) {
        if (!info[2]->IsUint32() || !info[3]->IsUint32()) {
            Nan::ThrowTypeError("Third and fourth arguments should be integers.");
            return;
        }

        n = Nan::To<uint32_t>(info[2]).FromJust();
        k = Nan::To<uint32_t>(info[3]).FromJust();
    }

    // Check if the arguments are Buffer instances
  if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution)) {
        Nan::ThrowTypeError("Arguments should be buffer objects.");
  return;
  }

    // Retrieve the data from the buffers
  const char *hdr = node::Buffer::Data(header);
    size_t hdr_length = node::Buffer::Length(header);

    if (hdr_length != 140) {
        // Invalid header length
        info.GetReturnValue().Set(Nan::New(false));
	  return;
  }

  const char *soln = node::Buffer::Data(solution);
    size_t soln_length = node::Buffer::Length(solution);

    // Create a vector from the solution buffer
    std::vector<unsigned char> vecSolution(soln, soln + soln_length);

    // Call the verification function
  bool result = verifyEH(hdr, vecSolution, n, k);

    // Set the return value
    info.GetReturnValue().Set(Nan::New(result));
}

void Init(v8::Local<v8::Object> exports) {
    Nan::Set(exports,
        Nan::New("verify").ToLocalChecked(),
        Nan::GetFunction(Nan::New<v8::FunctionTemplate>(Verify)).ToLocalChecked());
}

NODE_MODULE(equihashverify, Init)
