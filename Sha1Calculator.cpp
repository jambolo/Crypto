/** @file *//********************************************************************************************************

                                                  Sha1Calculator.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha1Calculator.cpp#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Sha1Calculator.h"

#include "Common.h"
#include <xutility>
#include <istream>

//	SHA-256 computation algorithm as documented by Wikipedia: http://en.wikipedia.org/wiki/SHA
//
//		Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating
//
//		Initialize variables:
//		h0 := 0x67452301
//		h1 := 0xEFCDAB89
//		h2 := 0x98BADCFE
//		h3 := 0x10325476
//		h4 := 0xC3D2E1F0
//		
//		Pre-processing:
//		append a single "1" bit to message
//		append "0" bits until message length = 448 = -64 (mod 512)
//		append length of message, in bits as 64-bit big-endian integer to message
//		
//		Process the message in successive 512-bit chunks:
//		break message into 512-bit chunks
//		for each chunk
//		    break chunk into sixteen 32-bit big-endian words w(i), 0 = i = 15
//		
//		    Extend the sixteen 32-bit words into eighty 32-bit words:
//		    for i from 16 to 79
//		        w(i) := (w(i-3) xor w(i-8) xor w(i-14) xor w(i-16)) leftrotate 1
//		
//		    Initialize hash value for this chunk:
//		    a := h0
//		    b := h1
//		    c := h2
//		    d := h3
//		    e := h4
//		
//		    Main loop:
//		    for i from 0 to 79
//		        if 0 = i = 19 then
//		            f := (b and c) or ((not b) and d)
//		            k := 0x5A827999
//		        else if 20 = i = 39
//		            f := b xor c xor d
//		            k := 0x6ED9EBA1
//		        else if 40 = i = 59
//		            f := (b and c) or (b and d) or (c and d)
//		            k := 0x8F1BBCDC
//		        else if 60 = i = 79
//		            f := b xor c xor d
//		            k := 0xCA62C1D6
//		
//		        temp := (a leftrotate 5) + f + e + k + w(i)
//		        e := d
//		        d := c
//		        c := b leftrotate 30
//		        b := a
//		        a := temp
//		
//		    Add this chunk's hash to result so far:
//		    h0 := h0 + a
//		    h1 := h1 + b 
//		    h2 := h2 + c
//		    h3 := h3 + d
//		    h4 := h4 + e
//		
//		digest = hash = h0 append h1 append h2 append h3 append h4 (expressed as big-endian)
//
//	Note: Instead of the formulation from the original FIPS PUB 180-1 shown, the following equivalent expressions
//	may be substituted into the appropriate ranges of the above pseudocode for improved efficiency:
//	
//		(0  = i = 19): f := d xor (b and (c xor d))         (alternative)
//		(20 = i = 39): f := b xor c xor d                   (unchanged)
//		(40 = i = 59): f := (b and c) or (d and (b or c))   (alternative 1)
//		(40 = i = 59): f := (b and c) + (d and (b xor c))   (alternative 2)
//		(60 = i = 79): f := b xor c xor d                   (unchanged)
//
//	The following are some examples of SHA1 digests:
//	
//	SHA1("The quick brown fox jumps over the lazy dog") ==
//	 "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
//	
//	SHA1("The quick brown fox jumps over the lazy cog") ==
//	 "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
//	
//	SHA1("") ==
//	 "da39a3ee5e6b4b0d3255bfef95601890afd80709"


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1Calculator::Sha1Calculator()
{
	Reset();
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Calculate( unsigned __int8 const * data, size_t size, unsigned __int8 * digest )
{
	Reset();
	Process( data, size );
	Finalize( digest );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Calculate( std::istream & stream, unsigned __int8 * digest )
{
	Reset();
	Process( stream );
	Finalize( digest );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Reset()
{
	m_digest[0]	= 0x67452301;
	m_digest[1]	= 0xEFCDAB89;
	m_digest[2]	= 0x98BADCFE;
	m_digest[3]	= 0x10325476;
	m_digest[4]	= 0xC3D2E1F0;

	m_tail			= 0;
	m_nProcessed	= 0;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Process( unsigned __int8 const * data, size_t size )
{
	// If there is already data in the buffer, then fill it.

	if ( m_tail > 0 )
	{
		size_t	n	= std::min( sizeof( m_buffer ) - m_tail, size );
		memcpy( &m_buffer[ m_tail ], data, n );

		m_tail += int( n );
		size -= n;
		data += n;
	}

	// If the buffer is full, then process it first

	if ( m_tail == sizeof( m_buffer ) )
	{
		ProcessChunk( m_buffer );
		m_nProcessed += sizeof( m_buffer );

		m_tail = 0;
	}

	// Process one chunk at a time

	while ( size > sizeof( m_buffer ) )
	{
		ProcessChunk( data );
		m_nProcessed += sizeof( m_buffer );

		size -= sizeof( m_buffer );
		data += sizeof( m_buffer );
	}

	// Put the leftover data in the buffer

	if ( size > 0 )
	{
		memcpy( m_buffer, data, size );
		m_tail = int( size );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Process( std::istream & stream )
{
	// Append to any data already in the buffer

	if ( stream.good() )
	{
		stream.read( reinterpret_cast<char*>( &m_buffer[m_tail] ), sizeof( m_buffer ) - m_tail );
		m_tail += stream.gcount();
	}

	// Repeatedly process and reload the buffer until the end of the file is reached. If the buffer is not full
	// when the end is reached, then just leave the data in it.

	while ( m_tail == sizeof( m_buffer ) )
	{
		// Process the buffer

		ProcessChunk( m_buffer );
		m_nProcessed += sizeof( m_buffer );
		m_tail = 0;

		// Reload the buffer

		if ( stream.good() )
		{
			stream.read( reinterpret_cast<char*>( m_buffer ), sizeof( m_buffer ) );
			m_tail = stream.gcount();
		}
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::Finalize( unsigned __int8 * digest )
{
	// Process the last chunk. The last chunk has a 1 bit (0x80 byte) appended, then is padded to 448 bits,
	// and then has a 64-bit size (of the data in bits) appended.

	// Append the 1 bit

	m_buffer[ m_tail ] = 0x80;
	++m_tail;

	// If the buffer has more than 56 bytes (including the appended 1 bit), it must be processed in two chunks
	// because there is not enough room for the appended size.

	// If the buffer has more than 56 bytes (including the appended 1 bit), process the first chunk.

	if ( m_tail > sizeof( m_buffer )-sizeof( unsigned __int64 ) )
	{
		// Pad to the end of the chunk
		memset( &m_buffer[ m_tail ], 0, sizeof( m_buffer )-m_tail );

		ProcessChunk( m_buffer );
		m_nProcessed += m_tail-1;	// -1 because we don't want to include the appended 1 bit

		m_tail = 0;
	}
	else
	{
		m_nProcessed += m_tail-1;	// -1 because we don't want to include the appended 1 bit
	}

	// Pad to the end of the chunk
	memset( &m_buffer[ m_tail ], 0, sizeof( m_buffer ) - m_tail );

	// Append the size (of the data in bits) 

	unsigned __int64 *	pEnd	= reinterpret_cast< unsigned __int64 * >( m_buffer + sizeof( m_buffer ) );
	pEnd[-1] = endian64( static_cast< unsigned __int64 >( m_nProcessed ) * 8 );

	// Process the final chunk

	ProcessChunk( m_buffer );

	// Endian-swap the digest before returning it

	for ( int i = 0; i < DIGEST_SIZE_IN_WORDS; ++i )
	{
		m_digest[i] = endian32( m_digest[i] );
	}

	memcpy( digest, m_digest, sizeof( m_digest ) );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha1Calculator::ProcessChunk( unsigned __int8 const * data )
{
	unsigned __int32	w[ NUMBER_OF_ROUNDS ];

	memcpy( w, data, WORDS_PER_CHUNK * sizeof( unsigned __int32 ) );

	// Endian-swap the input data

	for ( int i = 0; i < WORDS_PER_CHUNK; ++i )
	{
		w[i] = endian32( w[i] );
	}

	// Extend the sixteen 32-bit words into eighty 32-bit words:

	for ( int i = WORDS_PER_CHUNK; i < NUMBER_OF_ROUNDS; ++i )
	{
		w[i] = rotl( w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1 );
	}

	// Do the 80 rounds

	unsigned __int32 a	= m_digest[0];
	unsigned __int32 b	= m_digest[1];
	unsigned __int32 c	= m_digest[2];
	unsigned __int32 d	= m_digest[3];
	unsigned __int32 e	= m_digest[4];


	for ( int i = 0; i < NUMBER_OF_ROUNDS; ++i )
	{
		unsigned __int32 f;
		unsigned __int32 k;

		if ( i < 20 )
		{
            f = d ^ (b & (c ^ d));
            k = 0x5A827999;
		}
		else if ( i < 40 )
		{
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
		}
		else if ( i < 60 )
		{
            f = (b & c) | (d & (b | c));
            k = 0x8F1BBCDC;
		}
		else
		{
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
		}

		unsigned __int32	temp = rotl( a, 5 ) + f + e + k + w[i];
		e = d;
		d = c;
		c = rotl( b, 30 );
		b = a;
		a = temp;
	}

	m_digest[0] += a;
	m_digest[1] += b;
	m_digest[2] += c;
	m_digest[3] += d;
	m_digest[4] += e;
}


} // namespace Crypto