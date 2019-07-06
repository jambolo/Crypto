/** @file *//********************************************************************************************************

                                                 Sha256Calculator.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha256Calculator.cpp#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Sha256Calculator.h"

#include "Common.h"
#include <xutility>


//	SHA-256 computation algorithm as documented by Wikipedia: http://en.wikipedia.org/wiki/SHA
//
//		//Note: All variables are unsigned 32 bits and wrap modulo 2^32 when calculating
//		
//		//Initialize variables:
//		h0 := 0x6a09e667   //2^32 times the square root of the first 8 primes 2..19
//		h1 := 0xbb67ae85
//		h2 := 0x3c6ef372
//		h3 := 0xa54ff53a
//		h4 := 0x510e527f
//		h5 := 0x9b05688c
//		h6 := 0x1f83d9ab
//		h7 := 0x5be0cd19
//		
//		//Initialize table of round constants:
//		k(0..63) :=        //2^32 times the cube root of the first 64 primes 2..311
//		   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
//		   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
//		   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
//		   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
//		   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
//		   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
//		   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
//		   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
//		
//		//Pre-processing:
//		append a single "1" bit to  message
//		append "0" bits until message length = 448 = -64 (mod 512)
//		append length of message, in bits as 64-bit big-endian integer to message
//		
//		//Process the message in successive 512-bit chunks:
//		break message into 512-bit chunks
//		for each chunk
//		    break chunk into sixteen 32-bit big-endian words w(i), 0 = i = 15
//		
//		    //Extend the sixteen 32-bit words into sixty-four 32-bit words:
//		    for i from 16 to 63
//		        s0 := (w(i-15) rightrotate 7) xor (w(i-15) rightrotate 18) xor (w(i-15) rightshift 3)
//		        s1 := (w(i-2) rightrotate 17) xor (w(i-2) rightrotate 19) xor (w(i-2) rightshift 10)
//		        w(i) := w(i-16) + s0 + w(i-7) + s1
//		
//		    //Initialize hash value for this chunk:
//		    a := h0
//		    b := h1
//		    c := h2
//		    d := h3
//		    e := h4
//		    f := h5
//		    g := h6
//		    h := h7
//		
//		    //Main loop:
//		    for i from 0 to 63
//		        s0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
//		        maj := (a and b) or (b and c) or (c and a)
//		        t0 := s0 + maj
//		        s1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
//		        ch := (e and f) or ((not e) and g)
//		        t1 := h + s1 + ch + k(i) + w(i)
//		
//		        h := g
//		        g := f
//		        f := e
//		        e := d + t1
//		        d := c
//		        c := b
//		        b := a
//		        a := t0 + t1
//		
//		    //Add this chunk's hash to result so far:
//		    h0 := h0 + a
//		    h1 := h1 + b 
//		    h2 := h2 + c
//		    h3 := h3 + d
//		    h4 := h4 + e
//		    h5 := h5 + f
//		    h6 := h6 + g 
//		    h7 := h7 + h
//		
//		//Output the final hash value (big-endian):
//		digest = hash = h0 append h1 append h2 append h3 append h4 append h5 append h6 append h7
//
//		//Note: The ch and maj functions can be optimized the same way as described in SHA-256.


namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha256Calculator::Sha256Calculator()
{
	Reset();
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha256Calculator::Calculate( unsigned __int8 const * data, size_t size, unsigned __int8 * digest )
{
	Reset();
	Process( data, size );
	Finalize( digest );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha256Calculator::Calculate( std::istream & stream, unsigned __int8 * digest )
{
	Reset();
	Process( stream );
	Finalize( digest );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha256Calculator::Reset()
{
	m_digest[0]	= 0x6a09e667;
	m_digest[1]	= 0xbb67ae85;
	m_digest[2]	= 0x3c6ef372;
	m_digest[3]	= 0xa54ff53a;
	m_digest[4]	= 0x510e527f;
	m_digest[5]	= 0x9b05688c;
	m_digest[6]	= 0x1f83d9ab;
	m_digest[7]	= 0x5be0cd19;

	m_tail			= 0;
	m_nProcessed	= 0;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Sha256Calculator::Process( unsigned __int8 const * data, size_t size )
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

void Sha256Calculator::Process( std::istream & stream )
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

void Sha256Calculator::Finalize( unsigned __int8 * digest )
{
	// Process the last chunk. The last chunk has a 1 bit (0x80 byte) appended, then is padded to 448 bytes,
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
	memset( &m_buffer[ m_tail ], 0, sizeof( m_buffer )-m_tail );

	// Append the size (of the data in bits)

	unsigned __int64 *	pEnd	= reinterpret_cast< unsigned __int64 * >( m_buffer + sizeof( m_buffer ) );
	pEnd[-1] = endian64( static_cast< unsigned __int64 >( m_nProcessed ) * 8 );

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

void Sha256Calculator::ProcessChunk( unsigned __int8 const * data )
{
	static unsigned __int32 const	k[ NUMBER_OF_ROUNDS ] =
	{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	unsigned __int32	w[ NUMBER_OF_ROUNDS ];

	memcpy( w, data, WORDS_PER_CHUNK * sizeof( unsigned __int32 ) );

	// Endian-swap the input data

	for ( int i = 0; i < WORDS_PER_CHUNK; ++i )
	{
		w[i] = endian32( w[i] );
	}


	// Extend the sixteen 32-bit words into 64 32-bit words:

	for ( int i = WORDS_PER_CHUNK; i < NUMBER_OF_ROUNDS; ++i )
	{
		unsigned __int32	s0 = rotr( w[i-15],  7 ) ^ rotr( w[i-15], 18 ) ^ ( w[i-15] >>  3 );
		unsigned __int32	s1 = rotr( w[i- 2], 17 ) ^ rotr( w[i- 2], 19 ) ^ ( w[i- 2] >> 10 );

		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	// Do the 64 rounds

	unsigned __int32 a	= m_digest[0];
	unsigned __int32 b	= m_digest[1];
	unsigned __int32 c	= m_digest[2];
	unsigned __int32 d	= m_digest[3];
	unsigned __int32 e	= m_digest[4];
	unsigned __int32 f	= m_digest[5];
	unsigned __int32 g	= m_digest[6];
	unsigned __int32 h	= m_digest[7];


	for ( int i = 0; i < NUMBER_OF_ROUNDS; ++i )
	{
		unsigned __int32 s0		= rotr( a, 2 ) ^ rotr( a, 13 ) ^ rotr( a, 22 );
		unsigned __int32 maj	= ( a & b ) | ( b & c ) | ( c & a );
		unsigned __int32 t0		= s0 + maj;
		unsigned __int32 s1		= rotr( e, 6 ) ^ rotr( e, 11 ) ^ rotr( e, 25 );
		unsigned __int32 ch		= ( e & f ) | ( ~e & g );
		unsigned __int32 t1		= h + s1 + ch + k[i] + w[i];
		
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t0 + t1;
	}

	m_digest[0] += a;
	m_digest[1] += b;
	m_digest[2] += c;
	m_digest[3] += d;
	m_digest[4] += e;
	m_digest[5] += f;
	m_digest[6] += g;
	m_digest[7] += h;
}


} // namespace Crypto