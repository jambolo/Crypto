/** @file *//********************************************************************************************************

                                                   MD5Calculator.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/MD5Calculator.h#3 $

	$NoKeywords: $

 ********************************************************************************************************************/

#pragma once


// MD5.CC - source code for the C++/object oriented translation and
//			modification of MD5.

// Translation and modification (c) 1995 by Mordechai T. Abzug

// This translation/ modification is provided "as is," without express or
// implied warranty of any kind.

// The translator/ modifier does not claim (1) that MD5 will do what you think
// it does; (2) that this translation/ modification is accurate; or (3) that
// this software is "merchantible."  (Language for this disclaimer partially
// copied from the disclaimer below).

/* based on:

   MD5.H - header file for MD5C.C
   MDDRIVER.C - test driver for MD2, MD4 and MD5

   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.

*/

#include <istream>


namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! An MD5 digest calculator
//
//! This class computes MD5 digests using code based on an implementation by RSA Data Security, Inc.
//!

class Md5Calculator
{
	static int const	DIGEST_SIZE_IN_BITS		= 128;
	static int const	DIGEST_SIZE_IN_WORDS	= DIGEST_SIZE_IN_BITS/ 32;		// 4

	static int const	BITS_PER_CHUNK			= 512;
	static int const	BYTES_PER_CHUNK			= BITS_PER_CHUNK / 8;			// 64
	static int const	WORDS_PER_CHUNK			= BITS_PER_CHUNK / 32;			// 16

	static int const	NUMBER_OF_ROUNDS		= 5;

public:

	//! Size of the resulting digest in bytes
	static int const	DIGEST_SIZE			= DIGEST_SIZE_IN_BITS / 8;			// 16

	//! Default constructor
	Md5Calculator();

	// Destructor
	virtual ~Md5Calculator() {};

	//! Calculates the MD5 digest for a buffer
	void Calculate( unsigned __int8 const * data, size_t size, unsigned __int8 * digest );

	//! Calculates the MD5 digest for a stream
	void Calculate( std::istream & stream, unsigned __int8 * digest );

	//! @name Computation In Steps
	//@{

	//! Calling Process() with blocks of data a multiple of this size results in optimum performance.
	static int const	OPTIMAL_BLOCK_SIZE		= BYTES_PER_CHUNK;

	//! Resets the calculator
	void Reset();

	//! Processes a buffer
	void Process( unsigned __int8 const * data, size_t size );

	//! Processes a file
	void Process( std::istream & stream );

	//! Does the final computation and returns the digest
	void Finalize( unsigned __int8 * digest );

	//@}

private:

	// Processes a 512 bit chunk of data
	void ProcessChunk( unsigned __int8 const * data );

	unsigned __int32	m_digest[ DIGEST_SIZE_IN_WORDS ];	// Intermediate digest value
	unsigned __int8		m_buffer[ BYTES_PER_CHUNK ];		// Buffer for storing partial chunks
	int					m_tail;								// End of the data in the m_buffer
	size_t				m_nProcessed;						// Number of bytes processed so far
};


} // namespace Crypto