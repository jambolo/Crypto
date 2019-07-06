/** @file *//********************************************************************************************************

                                                        Md5.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Md5.h#3 $

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

//! An MD5 digest

class Md5
{
public:

	//! Size of an MD5 digest in bytes
	static int const	SIZE = 16;

	//! Default constructor
	Md5();

	//! Constructs an MD5 from a memory image
	Md5( unsigned __int8 const * pData, size_t size );

	//! Constructs an MD5 from a stream
	Md5( std::istream & stream );

	//! Constructs an MD5 from its text representation ( up to 32 hex characters)
	Md5( std::string const & text );

	//! Constructs an MD5 from its 0-terminated text representation (up to 32 hex characters)
	Md5( char const * pText );

	// Destructor
	virtual ~Md5();

	//! Returns the value as a text representation (with leading 0's)
	std::string ToString() const;

	//! Equality operator
	bool operator == ( Md5 const & y ) const;

	//! MD5 digest value
	unsigned __int8 m_digest[ SIZE ];
};


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream insertion operator
//
//! @param	stream	Stream
//! @param	md5		MD5 digest

inline std::ostream & operator<<( std::ostream & stream, Md5 const & md5 )
{
	stream << md5.ToString();

	return stream;
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

//! Formatted stream extraction operator
//
//! @param	stream	Stream
//! @param	md5		MD5 digest

inline std::istream & operator>>( std::istream & stream, Md5 & md5 )
{
	std::string	md5_string;

	stream >> md5_string;

	md5 = Md5( md5_string );

	return stream;
}


} // namespace Crypto