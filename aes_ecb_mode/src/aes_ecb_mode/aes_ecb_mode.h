//Copyright 2017 Sean Asadipour
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files 
// (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, 
// publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
// subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF 
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include <stddef.h>
#include <bcrypt.h>
// link the bcrypt library.
// this is the same as adding bcrypt.lib into your project settings file
#pragma comment (lib, "bcrypt")



/// <summary>
/// Encrypts or Decrypts the input buffer using AES library and the previously set AES key (referenced by the key id).
/// for ECB (electronic codebook) AES only 
/// </summary>
/// <param name="input_buffer">buffer to receive plaintext encrypted data.</param>
/// <param name="nInDatSize">actual data size (less than or equal to input buffer size)</param>
/// <param name="OutBuf">output buffer size.</param>
/// <param name="nOutBufSize">pointer to actual encrypted or decrpyted data size .</param>
/// <param name="pnOutDatSize">Size of the pn out dat.</param>
/// <param name="bDecrypt">if value is greater than 0 - decrypt, otherwise, encrypt.</param>
/// <param name="key">encryption key.</param>
/// <param name="key_len">length of encryption key (in bytes).</param>
/// <returns>
/// 0 if successful, otherwise, it returns windows error code 
/// </returns>
_Success_(return == 0) int AES_ECB(
	_In_reads_(nInDatSize)    unsigned char *InBuf, 
	_In_		unsigned long nInDatSize, 
	_Out_writes_(nOutBufSize) unsigned char *OutBuf, 
	_In_		unsigned long nOutBufSize, 
	_Out_opt_	unsigned long *pnOutDatSize, 
	_In_		unsigned char  bDecrypt, 
	_In_		unsigned char *key,
	_In_		unsigned long key_len
	);