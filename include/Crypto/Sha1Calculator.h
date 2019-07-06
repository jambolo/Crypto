/** @file *//********************************************************************************************************

                                                   Sha1Calculator.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha1Calculator.h#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#pragma once

#include <istream>


namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! An SHA-1 digest calculator
//
//! This class computes SHA-1 digests using the algorithm  documented in Wikipedia:
//! http://en.wikipedia.org/wiki/SHA

class Sha1Calculator
{
	static int const	DIGEST_SIZE_IN_BITS		= 160;
	static int const	DIGEST_SIZE_IN_WORDS	= DIGEST_SIZE_IN_BITS / 32;		// 5

	static int const	BITS_PER_CHUNK			= 512;
	static int const	BYTES_PER_CHUNK			= BITS_PER_CHUNK / 8;			// 64
	static int const	WORDS_PER_CHUNK			= BITS_PER_CHUNK / 32;			// 16

	static int const	NUMBER_OF_ROUNDS		= 80;

public:

	//! Size of the resulting digest in bytes
	static int const	DIGEST_SIZE				= DIGEST_SIZE_IN_BITS / 8;		// 20

	//! Default constructor
	Sha1Calculator();

	// Destructor
	virtual ~Sha1Calculator() {}

	//! Calculates the SHA-1 digest for a m_buffer
	void Calculate( unsigned __int8 const * data, size_t size, unsigned __int8 * digest );

	//! Calculates the SHA-1 digest for a stream
	void Calculate( std::istream & stream, unsigned __int8 * digest );

	//! @name Computation In Steps
	//@{

	//! Calling Process() with blocks of data a multiple of this size results in optimum performance.
	static int const	OPTIMAL_BLOCK_SIZE		= BYTES_PER_CHUNK;

	//! Resets the calculator
	void Reset();

	//! Processes a m_buffer
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