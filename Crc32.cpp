/** @file *//********************************************************************************************************

                                                      Crc32.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Crc32.cpp#3 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Crc32.h"

#include "Crc32Calculator.h"
#include "Common.h"

namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Crc32::Crc32( unsigned __int8 const * pData, size_t size )
{
	m_value = Crc32Calculator().Calculate( pData, size );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Crc32::Crc32( std::istream & stream )
{
	m_value = Crc32Calculator().Calculate( stream );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Crc32::Crc32( std::string const & text )
{
	m_value = 0;

	for ( std::string::const_iterator pC = text.begin(); pC != text.end(); ++pC )
	{
		m_value *= 16;
		m_value += atox( *pC );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Crc32::Crc32( char const * text )
{
	m_value = 0;

	while ( *text != 0 )
	{
		m_value *= 16;
		m_value += atox( *text );
		++text;
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

std::string Crc32::ToString() const
{
	std::string	result( 8, '0' );

	int	i = 7;
	for ( unsigned __int32 value = m_value; value != 0; value >>= 4 )
	{
		result[i] = xtoa( value & 0x0000000f );
		--i;
	}

	return result;
}


} // namespace Crypto