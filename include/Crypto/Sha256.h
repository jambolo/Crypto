/** @file *//********************************************************************************************************

                                                       Sha256.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha256.h#2 $

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

//! An SHA-256 digest

class Sha256
{
public:

	//! Size of an SHA-256 digest in bytes
	static size_t const	SIZE = 32;

	//! Default constructor
	Sha256();

	//! Constructs an SHA-256 from a memory image
	Sha256( unsigned __int8 const * pData, size_t size );

	//! Constructs an SHA-256 from a stream
	Sha256( std::istream & stream );

	//! Constructs an SHA-256 from its text representation ( up to 64 hex characters)
	Sha256( std::string const & text );

	//! Constructs an SHA-256 from its 0-terminated text representation (up to 64 hex characters)
	Sha256( char const * pText );

	// Destructor
	virtual ~Sha256();

	//! Returns the value as a text representation (with leading 0's)
	std::string ToString() const;

	//! Equality operator
	bool operator == ( Sha256 const & y ) const;

	unsigned __int8 m_value[ SIZE ];	//!< Value
};


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream insertion operator
//
//! @param	stream	Stream
//! @param	sha256	SHA-256 digest

inline std::ostream & operator<<( std::ostream & stream, Sha256 const & sha256 )
{
	stream << sha256.ToString();

	return stream;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream extraction operator
//
//! @param	stream	Stream
//! @param	sha256	SHA-256 digest

inline std::istream & operator>>( std::istream & stream, Sha256 & sha256 )
{
	std::string	sha256_string;

	stream >> sha256_string;

	sha256 = Sha256( sha256_string );

	return stream;
}


} // namespace Crypto