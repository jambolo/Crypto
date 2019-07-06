/********************************************************************************************************************

                                               Crc32CalculatorTest.cpp

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Test/Crc32CalculatorTest.cpp#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#include "Crc32CalculatorTest.h"

#include "Misc/Random.h"
#include "Misc/Etc.h"

#include <sstream>
#include <fstream>

using namespace Crypto;

CPPUNIT_TEST_SUITE_REGISTRATION( Crc32CalculatorTest );

namespace
{
	unsigned __int32	s_ReferenceCrcTable[256];
	unsigned char		testbuffer[ 256 ];

} // anonymous namespace


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::setUp()
{
	// Initialize the reference code

	InitializeReferenceAlgorithm();

	// Initialize the test buffer

	Random	rng( 0 );

	for ( int i = 0; i < (int)elementsof( testbuffer ); ++i )
	{
		testbuffer[i] = rng.Get();
	}
}

/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::tearDown()
{
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestSizeOfCrc32()
{
	CPPUNIT_ASSERT_EQUAL_MESSAGE( "The size of Crc32 is not 32 bits.", sizeof( __int32 ), sizeof( Crc32 ) );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestConstructor()
{
	CPPUNIT_ASSERT_NO_THROW( Crc32Calculator() );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestOpen()
{
	Crc32	crc(0xDEADBEEF);

	Crc32Calculator::Open( &crc );

	CPPUNIT_ASSERT_EQUAL( 0xffffffff, crc );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestUpdateByte()
{
	for ( int i = 0; i < 256; ++i )
	{
		Crc32 const	expected	= CalculateReferenceUpdateValue( 0, i );
		Crc32		actual		= 0;
		
		Crc32Calculator::Update( i, &actual );

		std::ostringstream	message;
		message << "Crc table mismatch at element " << i << ".";

		CPPUNIT_ASSERT_EQUAL_MESSAGE( message.str(), expected, actual );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestUpdateBuffer()
{
	for ( int i = 0; i <= 256; ++i )
	{
		Crc32 const	expected	= CalculateReferenceUpdate( 0xBADC0DE, testbuffer, i );
		Crc32		actual		= 0xBADC0DE;
		
		Crc32Calculator::Update( testbuffer, i, &actual );

		std::ostringstream	message;
		message << "Failed updating the CRC for a buffer of size " << i << " bytes.";

		CPPUNIT_ASSERT_EQUAL_MESSAGE( message.str(), expected, actual );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestClose()
{
	Crc32 const	openCrc		= 0xDEADBEEF;
	Crc32		closedCrc	= openCrc;

	Crc32Calculator::Close( &closedCrc );

	CPPUNIT_ASSERT_EQUAL( (Crc32)( openCrc ^ 0xffffffff ), closedCrc );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestBufferCalculate()
{
	for ( int i = 0; i <= 256; ++i )
	{
		Crc32 const	expected	= CalculateReferenceCrc( testbuffer, i );
		Crc32 const	actual		= Crc32Calculator::Calculate( testbuffer, i );

		std::ostringstream	message;
		message << "Failed generating a CRC for a buffer of size " << i << " bytes.";

		CPPUNIT_ASSERT_EQUAL_MESSAGE( message.str(), expected, actual );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestCStringCalculate()
{
	char const * const strings[] =
	{
		"",
		"a",
		"bc",
		"def",
		"ghij",
		"The quick brown fox jumped over the lazy dog."
	};

	for ( int i = 0; i < elementsof( strings ); ++i )
	{
		Crc32 const	expected	= CalculateReferenceCrc( (unsigned char const *)strings[i], (size_t)strlen( strings[i] ) );
		Crc32 const	actual		= Crc32Calculator::Calculate( strings[i] );

		std::ostringstream	message;
		message << "Failed generating a CRC for the string " << '"' << strings[i] << '"';

		CPPUNIT_ASSERT_EQUAL_MESSAGE( message.str(), expected, actual );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

void Crc32CalculatorTest::TestStringCalculate()
{
	std::string strings[] =
	{
		"",
		"a",
		"bc",
		"def",
		"ghij",
		"The quick brown fox jumped over the lazy dog."
	};

	for ( int i = 0; i < elementsof( strings ); ++i )
	{
		Crc32 const	expected	= CalculateReferenceCrc( (unsigned char const *)strings[i].c_str(), strings[i].size() );
		Crc32 const	actual		= Crc32Calculator::Calculate( strings[i] );

		std::ostringstream	message;
		message << "Failed generating a CRC for the string " << '"' << strings[i] << '"';

		CPPUNIT_ASSERT_EQUAL_MESSAGE( message.str(), expected, actual );
	}
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

#define FILENAME	"\\WINDOWS\\notepad.exe"

void Crc32CalculatorTest::TestInputStreamCalculate()
{
	Crc32	expected;
	Crc32	actual;

	{
		std::ifstream	file( FILENAME, std::ios_base::in|std::ios_base::binary|std::ios_base::ate );
		CPPUNIT_ASSERT_MESSAGE( "Crc32Calculator::Calculate( std::istream & stream ) cannot be tested because the file \"" FILENAME "\" cannot be opened.", file.is_open() );

		int const	size	= file.tellg();
		char *		buffer	= new char [ size ];

		file.seekg ( 0, std::ios::beg );
		file.read( buffer, size );

		expected = CalculateReferenceCrc( (unsigned char *)buffer, size );

		delete[] buffer;
	}

	{
		std::ifstream	file( FILENAME, std::ios_base::in|std::ios_base::binary );
		CPPUNIT_ASSERT_MESSAGE( "Crc32Calculator::Calculate( std::istream & stream ) cannot be tested because the file \"" FILENAME "\" cannot be opened.", file.is_open() );

		actual = Crc32Calculator::Calculate( file );
	}

	CPPUNIT_ASSERT_EQUAL_MESSAGE( "Failed generating a CRC for the file \"" FILENAME "\".", expected, actual );
}


/********************************************************************************************************************/
/*																													*/
/********************************************************************************************************************/

// This reference code comes from the PNG library which is implemented according to IS0 3309

void Crc32CalculatorTest::InitializeReferenceAlgorithm()
{
	/* Make the table for a fast CRC. */

	Crc32 c;
	int n, k;

	for (n = 0; n < 256; n++)
	{
		c = (Crc32) n;
		for (k = 0; k < 8; k++)
		{
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c = c >> 1;
		}
		s_ReferenceCrcTable[n] = c;
	}
}

Crc32 Crc32CalculatorTest::CalculateReferenceCrc( unsigned char const * buf, int len )
{
	return CalculateReferenceUpdate( 0xffffffff, buf, len ) ^ 0xffffffff;
}

Crc32 Crc32CalculatorTest::CalculateReferenceUpdate( Crc32 crc, unsigned char const * buf, int len )
{
	for ( int n = 0; n < len; n++ )
	{
		crc = CalculateReferenceUpdateValue( crc, buf[n] );
	}

	return crc;
}

Crc32 Crc32CalculatorTest::CalculateReferenceUpdateValue( Crc32 crc, unsigned char x )
{
    return s_ReferenceCrcTable[ ( crc ^ x ) & 0xff ] ^ ( crc >> 8 );
}
