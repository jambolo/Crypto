/** @file *//********************************************************************************************************

                                                       Sha1.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha1.cpp#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Sha1.h"

#include "Sha1Calculator.h"
#include "Common.h"

#include <cstring>
#include <xutility>


namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::Sha1()
{
	memset( &m_value, 0, sizeof m_value );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::~Sha1()
{
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::Sha1( unsigned __int8 const * pData, size_t size )
{
	Sha1Calculator().Calculate( pData, size, m_value );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::Sha1( std::istream & stream )
{
	Sha1Calculator().Calculate( stream, m_value );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::Sha1( std::string const & text )
{
	HexToBinary( text, m_value, SIZE );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

Sha1::Sha1( char const * text )
{
	HexToBinary( text, m_value, SIZE );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

std::string Sha1::ToString() const
{
	return BinaryToHex( m_value, SIZE );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

bool Sha1::operator == ( Sha1 const & y ) const
{
	return ( memcmp( m_value, y.m_value, sizeof( m_value ) ) == 0 );
}


} // namespace Crypto