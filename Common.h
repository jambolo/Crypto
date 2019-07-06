/********************************************************************************************************************

                                                       Common.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Common.h#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#pragma once

#include <string>


namespace Crypto
{


void HexToBinary( std::string const & text, unsigned __int8 * buffer, size_t size );
void HexToBinary( char const * text, unsigned __int8 * buffer, size_t size );
std::string BinaryToHex( unsigned __int8 const * buffer, size_t size );

inline int atox( char c )
{
	unsigned x;

	// Handle '0' - '9'

	x = c - '0';

	// Handle 'A' - 'F'

	if ( x > 9 )
		x -= 'A' - '0' - 10;

	// Handle 'a' - 'f'

	if ( x > 15 )
		x -= 'a' - 'A';

	return x;
}


inline char xtoa( int x )
{
	return ( x < 10 ) ? ( '0' + x ) : ( 'a' - 10 + x );
}

inline unsigned __int16 endian16( unsigned __int16 x )
{
	unsigned __int8 const	high	= unsigned __int8( ( ( x & 0xff00 ) >> 8 ) & 0x00ff );
	unsigned __int8 const	low		= unsigned __int8( x & 0x00ff );

	return  ( unsigned __int16( low ) << 8 | unsigned __int16( high ) );
}

inline unsigned __int32 endian32( unsigned __int32 x )
{
	unsigned __int16 const	high	= unsigned __int16( ( ( x & 0xffff0000 ) >> 16 ) & 0x0000ffff );
	unsigned __int16 const	low		= unsigned __int16( x & 0x0000ffff );

	return  ( unsigned __int32( endian16( low ) ) << 16 | unsigned __int32( endian16( high ) ) );
}

inline unsigned __int64 endian64( unsigned __int64 x )
{
	unsigned __int32 const	high	= unsigned __int32( ( ( x & 0xffffffff00000000 ) >> 32 ) & 0x00000000ffffffff );
	unsigned __int32 const	low		= unsigned __int32( x & 0x00000000ffffffff );

	return ( unsigned __int64( endian32( low ) ) << 32 | unsigned __int64( endian32( high ) ) );
}

//template < typename T >
//inline T rotl( T x, int n )
//{
//	int const	SIZE_IN_BITS	= sizeof( T ) * 8;
//	T carry	= ( x >> ( SIZE_IN_BITS-n ) ) & ( ( 1 << n ) - 1 );
//	return ( x << n ) | carry;
//}
  
//template < typename T >
//inline T rotr( T x, int n )
//{
//	int const	SIZE_IN_BITS	= sizeof( T ) * 8;
//	T carry	= ( x & ( ( 1 << n ) - 1 ) ) << ( SIZE_IN_BITS-n );
//	return ( x >> n ) | carry;
//}

//template <>
inline unsigned __int32 rotl( unsigned __int32 x, int n )
{
	return _rotl( x, n );
}

//template <>
inline unsigned __int32 rotr( unsigned __int32 x, int n )
{
	return _rotr( x, n );
}


} // namespace Crypto
