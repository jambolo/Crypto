/** @file *//********************************************************************************************************

                                                        Sha1.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Sha1.h#2 $

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

//! An SHA-1 digest

class Sha1
{
public:

	//! Size of an SHA-1 digest in bytes
	static size_t const	SIZE = 20;

	//! Default constructor
	Sha1();

	//! Constructs an SHA-1 from a memory image
	Sha1( unsigned __int8 const * pData, size_t size );

	//! Constructs an SHA-1 from a stream
	Sha1( std::istream & stream );

	//! Constructs an SHA-1 from its text representation ( up to 40 hex characters)
	Sha1( std::string const & text );

	//! Constructs an SHA-1 from its 0-terminated text representation (up to 40 hex characters)
	Sha1( char const * pText );

	// Destructor
	virtual ~Sha1();

	//! Returns the value as a text representation (with leading 0's)
	std::string ToString() const;

	//! Equality operator
	bool operator == ( Sha1 const & y ) const;

	//! SHA-1 digest value
	unsigned __int8 m_value[ SIZE ];
};


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream insertion operator
//
//! @param	stream	Stream
//! @param	sha1	SHA-1 digest

inline std::ostream & operator<<( std::ostream & stream, Sha1 const & sha1 )
{
	stream << sha1.ToString();

	return stream;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream extraction operator
//
//! @param	stream	Stream
//! @param	sha1	SHA-1 digest

inline std::istream & operator>>( std::istream & stream, Sha1 & sha1 )
{
	std::string	sha1_string;

	stream >> sha1_string;

	sha1 = Sha1( sha1_string );

	return stream;
}


} // namespace Crypto