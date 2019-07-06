/********************************************************************************************************************

                                                      Common.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Common.cpp#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Common.h"

namespace Crypto
{


void HexToBinary( std::string const & text, unsigned __int8 * buffer, size_t size )
{
	// Initialize leading bytes to 0 in case the text does not have the full number of digits (e.g. no leading 0's).

	memset( buffer, 0, size );

	std::string::const_iterator	pText	= text.begin();

	// Number of text digits to process. Clamp to the max.
	size_t	ndigits	= std::min<size_t>( text.size(), size * 2 );

	// If the the text does not have the full number of digits then it is assumed that the text contains the
	// rightmost digits and leading 0's have been dropped.

	unsigned __int8 *	pValue	= &buffer[ size - ( ndigits + 1 ) / 2 ];

	// Handle the odd digits case (this can happen if there are no leading 0's)

	if ( ( ndigits & 1 ) != 0 )
	{
		*pValue++ = atox( *pText );
		++pText;
		--ndigits;
	}

	// Convert two digits at a time until the end of the value is reached

	while ( ndigits > 0 )
	{
		*pValue++ = atox( pText[0] ) * 16 + atox( pText[1] );
		pText += 2;
		ndigits -= 2;
	}
}


void HexToBinary( char const * text, unsigned __int8 * buffer, size_t size )
{
	// Initialize leading bytes to 0 in case the text does not have the full
	// number of digits (e.g. no leading 0's).

	memset( buffer, 0, size );

	// Number of text digits to process. Clamp to the max.
	size_t	ndigits	= std::min<size_t>( strlen( text ), size * 2 );

	// If the the text does not have the full number of digits then it is
	// assumed that the text contains the rightmost digits and leading
	// 0's have been dropped.
	unsigned __int8 *	pValue	= &buffer[ size - ( ndigits + 1 ) / 2 ];

	// Handle the odd digits case (this can happen if there are no leading 0's)

	if ( ( ndigits & 1 ) != 0 )
	{
		*pValue++ = atox( *text );
		++text;
		--ndigits;
	}

	// Convert two digits at a time until the end of the value is reached

	while ( ndigits > 0 )
	{
		*pValue++ = atox( text[0] ) * 16 + atox( text[1] );
		text += 2;
		ndigits -= 2;
	}
}


std::string BinaryToHex( unsigned __int8 const * buffer, size_t size )
{
	std::string text( size * 2, '0' );
	std::string::iterator pText = text.begin();

	for ( size_t i = 0; i < size; ++i )
	{
		*pText++ = xtoa( buffer[ i ] / 16 );
		*pText++ = xtoa( buffer[ i ] % 16 );
	}

	return text;
}

} // namespace Crypto