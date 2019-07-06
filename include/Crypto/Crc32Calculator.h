/** @file *//********************************************************************************************************

                                                  Crc32Calculator.h

						                    Copyright 2003, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Crc32Calculator.h#3 $

	$NoKeywords: $

*********************************************************************************************************************/

#pragma once

#include <string>
#include <istream>


namespace Crypto
{

/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! A CRC-32 calculator
//
//! There appears to be no "standard" CRC-32 algorithm, though the one this implementation is based on might be
//! considered a standard since it is so popular. I based this implementation on several sources. The code in those
//! sources were very similar, so they are all probably derived from the same source. All of the sources claim
//! that this algorithm is described in the ISO standard 3309. I have not seen the standard, so I cannot verify
//! those claims.
//!
//! The code for calculating the CRC is as follows:
//!
//! @code
//! 	crc =	0xffffffff;
//!		for	( int i = 0; i < size; ++i )
//!		{
//!			crc = ( crc >> 8) ^ table[ ( crc & 0xFF ) ^ paData[i] ];
//!		}
//! 	crc ^=	0xffffffff;
//! @endcode
//!
//! The algorithm for generating @a table is as follows. The polynomial is 0xEDB88320, but often it is shown reversed
//! as 0x04C11DB7.
//!
//! @code
//!		unsigned __int32 const	POLYNOMIAL	= 0xEDB88320;
//!
//!		for	( int i	= 0; i < 256; i++ )
//!		{
//!			unsigned __int32		x;
//!
//!			x = i;
//!
//!			for	(int j = 0;	j < 8; j++)
//!			{
//!				bool const	b	= ( ( x & 1 ) != 0 );
//!
//!				x >>= 1;
//!				if ( b )
//!				{
//!					x ^= POLYNOMIAL;
//!				}
//!			}
//!
//!			table[i] =	x;
//!		}
//! @endcode

class Crc32Calculator
{
public:

	//! Constructor
	Crc32Calculator();

	// Destructor
	virtual ~Crc32Calculator();

	//! Returns a CRC-32 value from a buffer of a given size.
	unsigned __int32 Calculate( unsigned __int8 const * paData, size_t size );

	//! Returns a CRC-32 value from an input stream.
	unsigned __int32 Calculate( std::istream & stream );

	//! Returns a CRC-32 value from a C string.
	unsigned __int32 Calculate( char const * string );

	//! Returns a CRC-32 value from a string.
	unsigned __int32 Calculate( std::string const & string );

	//! @name Computation In Steps
	//@{

	//! Restarts calculation of a CRC.
	void Reset();

	//! Updates the CRC with the given character.
	void Process( unsigned __int8 c );

	//! Updates the CRC with a buffer.
	void Process( unsigned __int8 const * paData, size_t size );

	//! Updates the CRC with a stream.
	void Process( std::istream & stream );

	//! Finalizes a CRC.
	void Finalize( unsigned __int32 * pCrc );

	//@}

private:
	
	unsigned __int32	m_crc;

	static int const	LOOKUP_TABLE_SIZE	= 256;

	// Generates the CRC32 lookup table.
	static void GenerateLookupTable( unsigned __int32 aTable[ LOOKUP_TABLE_SIZE ] );

	static unsigned __int32	m_lookupTable[ LOOKUP_TABLE_SIZE ];	// The lookup table

};


} // namespace Crypto
