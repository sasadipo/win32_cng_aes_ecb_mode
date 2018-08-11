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

#include "stdafx.h"

/// <summary>
/// Converts the nt status to win32 error.
/// </summary>
/// <param name="_ntstatus">The ntstatus.</param>
/// <returns>win32 error.</returns>
DWORD ConvertBcryptStatusToWin32Error(NTSTATUS _ntstatus)
{
	DWORD oldError;
	DWORD result;
	DWORD br_;
	OVERLAPPED ovlp_ = {0};
	if(BCRYPT_SUCCESS(_ntstatus))
	{
		return ERROR_SUCCESS;
	}
	ovlp_.Internal = (LONG)_ntstatus;
	ovlp_.InternalHigh = 0;
	ovlp_.Offset = 0;
	ovlp_.OffsetHigh = 0;
	ovlp_.hEvent = 0;
	oldError = GetLastError();
	GetOverlappedResult(NULL, &ovlp_, &br_, FALSE);
	result = GetLastError();
	SetLastError(oldError);
	return result;
}

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
	)
{
	NTSTATUS bcryptResult = 0;
	
	unsigned long bytes_done = 0;
	unsigned char buffer[16] = { 0 };

	BCRYPT_ALG_HANDLE algHandle = NULL;
	BCRYPT_KEY_HANDLE keyHandle = NULL;

	size_t encrypted_data_len = 0;
	unsigned long blockLength = 0;


	// open aes provider
	bcryptResult = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if(!(BCRYPT_SUCCESS(bcryptResult)))
	{
		goto exit_;
	}
	// set chaining mode
	bcryptResult = BCryptSetProperty(algHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

	if(!(BCRYPT_SUCCESS(bcryptResult)))
	{
		goto exit_;
	}

	// get block len (should be 16)
	bcryptResult = BCryptGetProperty(algHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)&blockLength, sizeof(blockLength), &bytes_done, 0);
	if(!(BCRYPT_SUCCESS(bcryptResult)))
	{
		goto exit_;
	}

	//generate symmetric AES key
	bcryptResult = BCryptGenerateSymmetricKey(algHandle, &keyHandle, 0, 0, (PUCHAR)key, key_len, 0);
	if(!(BCRYPT_SUCCESS(bcryptResult)))
	{
		goto exit_;
	}

	// encrypt or decrypt data in chunks
	for (encrypted_data_len = 0; encrypted_data_len < nInDatSize; encrypted_data_len += bytes_done)
	{
		if(bDecrypt)
		{
			bcryptResult = BCryptDecrypt(keyHandle, (PUCHAR)&InBuf[encrypted_data_len], blockLength, NULL, 0, 0, buffer, sizeof(buffer), &bytes_done, 0);
		}
		else
		{
			bcryptResult = BCryptEncrypt(keyHandle, (PUCHAR)&InBuf[encrypted_data_len], blockLength, NULL, 0, 0, buffer, sizeof(buffer), &bytes_done, 0);
		}

		if(!(BCRYPT_SUCCESS(bcryptResult)))
		{
			goto exit_;
		}
		if(encrypted_data_len > nOutBufSize)
		{
			goto exit_;
		}

		CopyMemory(&OutBuf[encrypted_data_len], buffer, bytes_done);
		ZeroMemory(buffer, sizeof(buffer));
	}
	
	if(pnOutDatSize) 
	{
		*pnOutDatSize = (unsigned long)encrypted_data_len;
	}

exit_:

	// Cleanup
	if(keyHandle!= NULL)
	{
		BCryptDestroyKey(keyHandle);
		keyHandle = NULL;
	}

	if(algHandle != NULL)
	{
		BCryptCloseAlgorithmProvider(algHandle, 0);
	}

	return ConvertBcryptStatusToWin32Error(bcryptResult);
}

// you can remove this if you don't require unit testing
#pragma region unit_test

// - for hex string to bin conversion 
#include <wincrypt.h>
#pragma comment (lib, "crypt32")
// -
#include <stdio.h>
#include <comdef.h>
#include <strsafe.h>

BOOL ConvertBinaryToHexString(
	_Out_ PBYTE _data,
	_In_ size_t _len,
	_Out_writes_(szOutputBufferLen) wchar_t * wstrOutput,
	_In_ size_t szOutputBufferLen)
{
	DWORD dwStringLength = (DWORD)szOutputBufferLen;
	BOOL bReturn = FALSE;
	DWORD _i = 0;
	if((_data != NULL) && (wstrOutput != NULL))
	{
		return CryptBinaryToStringW(_data,(DWORD) _len,CRYPT_STRING_NOCRLF|CRYPT_STRING_HEXRAW, wstrOutput, &dwStringLength); 
	}
	return bReturn;
}


int wmain(int argc, wchar_t* argv[])
{
	wchar_t wstrBuffer[512] = {0};
	wchar_t wstrEncryptBuffer[4096] = {0};

	unsigned char encrypted_data[2048] = {0};

	// for now, just hard code a 128 bit key we can use
	unsigned char encryption_key[] = 
	{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5,0x6,0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
	};
	unsigned long encryption_key_length = 0;
	unsigned long output_data_length = 0;

	HRESULT _hr = S_OK;

	wprintf_s(L"enter up to 512 unicode character string to encrypt: \n");
	_hr = StringCchGetsW(wstrBuffer, _countof(wstrBuffer));
	if(FAILED(_hr))
	{
		_com_error err_(_hr);
		wprintf_s(L"\nerror: failed to get input buffer.\n%s\n", err_.ErrorMessage());
		goto exit_;
	}
	// test encryption
	if(AES_ECB((PUCHAR)wstrBuffer, sizeof(wstrBuffer), encrypted_data, sizeof(encrypted_data), &output_data_length, FALSE, encryption_key, sizeof(encryption_key)) != ERROR_SUCCESS)
	{
		wprintf_s(L"\nerror: failed to encrypt buffer input.\n");
		goto exit_;
	}

	if(!ConvertBinaryToHexString(encrypted_data, output_data_length, wstrEncryptBuffer, _countof(wstrEncryptBuffer)))
	{
		wprintf_s(L"\nerror %lu: failed to convert encrypted binary data to string form.\n", GetLastError());
		goto exit_;
	}

	wprintf_s(L"\nAES ECB encrypted buffer output:\n%s\n", wstrEncryptBuffer);
	ZeroMemory(wstrBuffer, sizeof(wstrBuffer));
	// test decryption
	if(AES_ECB(encrypted_data, output_data_length,(PUCHAR)wstrBuffer, sizeof(wstrBuffer),  &output_data_length, TRUE, encryption_key, sizeof(encryption_key)) != ERROR_SUCCESS)
	{
		wprintf_s(L"\nerror: failed to decrypt buffer input.\n");
		goto exit_;
	}

	wprintf_s(L"\nOriginal string:\n%s\n", wstrBuffer);
exit_:

	_wsystem(L"Pause");
	return 0;
}

#pragma endregion
