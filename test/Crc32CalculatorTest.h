/********************************************************************************************************************

                                                Crc32CalculatorTest.h

						                    Copyright 2004, John J. Bolton
	--------------------------------------------------------------------------------------------------------------

	$Header: //depot/Libraries/Crypto/Test/Crc32CalculatorTest.h#2 $

	$NoKeywords: $

 ********************************************************************************************************************/

#pragma once

#include "../Crc32Calculator.h"
#include "../Crc32.h"

#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/TestFixture.h>

class Crc32CalculatorTest : public CPPUNIT_NS::TestFixture
{
	CPPUNIT_TEST_SUITE( Crc32CalculatorTest );
	CPPUNIT_TEST( TestSizeOfCrc32 );
	CPPUNIT_TEST( TestConstructor );
	CPPUNIT_TEST( TestOpen );
	CPPUNIT_TEST( TestUpdateByte );
	CPPUNIT_TEST( TestUpdateBuffer );
	CPPUNIT_TEST( TestClose );
	CPPUNIT_TEST( TestBufferCalculate );
	CPPUNIT_TEST( TestCStringCalculate );
	CPPUNIT_TEST( TestStringCalculate );
	CPPUNIT_TEST( TestInputStreamCalculate );
	CPPUNIT_TEST_SUITE_END();

public:

	void setUp();
	void tearDown();

	void TestSizeOfCrc32();
	void TestConstructor();
	void TestOpen();
	void TestUpdateByte();
	void TestUpdateBuffer();
	void TestClose();
	void TestBufferCalculate();
	void TestCStringCalculate();
	void TestStringCalculate();
	void TestInputStreamCalculate();

private:

	void InitializeReferenceAlgorithm();
	Crypto::Crc32 CalculateReferenceUpdateValue( Crypto::Crc32 crc, unsigned char x );
	Crypto::Crc32 CalculateReferenceUpdate( Crypto::Crc32 crc, unsigned char const * buf, int len );
	Crypto::Crc32 CalculateReferenceCrc( unsigned char const * buf, int len );
};
