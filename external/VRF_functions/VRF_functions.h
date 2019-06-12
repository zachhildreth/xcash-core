#ifndef VRF_FUNCTIONS_H_   /* Include guard */
#define VRF_FUNCTIONS_H_

/*
Copyright (c) 2018 - 2019 Amir Hossein Alikhah Mishamandani
Copyright (c) 2018 Algorand LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "convert.h"
#include "vrf.h"
#include "sha512EL.h"
#include "ed25519_ref10.h"

int 
crypto_hash_sha512_init(crypto_hash_sha512_state *state);

int
crypto_vrf_verify(unsigned char *output, const unsigned char *pk,
		  const unsigned char *proof, const unsigned char *m,
		  const unsigned long long mlen);

int
crypto_vrf_is_valid_key(const unsigned char *pk);
#endif