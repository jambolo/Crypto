/** @file *//********************************************************************************************************

                                                       Crc32.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Crc32.h#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#pragma once

#include <string>
#include <iostream>


namespace Crypto
{


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! A CRC-32 value

class Crc32
{
public:

	//! Size of a CRC-32 value in bytes
	static size_t const	SIZE = 4;

	//! Default constructor
	Crc32()	{}

	//! Constructs a CRC-32 from a memory image
	Crc32( unsigned __int8 const * pData, size_t size );

	//! Constructs an CRC-32 from a stream
	Crc32( std::istream & stream );

	//! Constructs a CRC-32 from its text representation ( up to 8 hex characters)
	Crc32( std::string const & text );

	//! Constructs a CRC-32 from its 0-terminated text representation (up to 8 hex characters)
	Crc32( char const * pText );

	// Destructor
	virtual ~Crc32() {}

	//! Returns the value as a text representation (with leading 0's)
	std::string ToString() const;

	//! Equality operator
	bool operator == ( Crc32 const & y ) const	{ return m_value == y.m_value; }

	unsigned __int32 m_value;	//!< Value
};


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream insertion operator
//
//! @param	stream	Stream
//! @param	crc32	CRC-32 value

inline std::ostream & operator<<( std::ostream & stream, Crc32 const & crc32 )
{
	stream << crc32.ToString();

	return stream;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream extraction operator
//
//! @param	stream	Stream
//! @param	crc32	CRC-32 value

inline std::istream & operator>>( std::istream & stream, Crc32 & crc32 )
{
	std::string	crc32_string;

	stream >> crc32_string;

	crc32 = Crc32( crc32_string );

	return stream;
}


} // namespace Crypto