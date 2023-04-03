/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <exec/types.h>
#include <proto/exec.h>
#include <common/endian.h>
#include <common/bcm_i2c.h>
#include <common/debug.h>
#include <i2c_private.h>

#define D(x) /* x */

#define RESULT(isSuccess, ubIoError, ubAllocError) ((ubAllocError << 16) | (ubIoError << 8) | (isSuccess))

ULONG ReceiveI2C(
	REGARG(UBYTE ubAddress, "d0"),
	REGARG(UWORD uwDataSize, "d1"),
	REGARG(UBYTE pData[], "a0"),
	REGARG(struct I2C_Base *i2cBase, "a6")
)
{
	D(bug("ReceiveI2C(%02x, %d, %08x)\n", ubAddress, uwDataSize, pData));

	// TODO: Semaphore shared with SendI2C
	// bcm expects read/write bit to be omitted from address
	ubAddress >>= 1;

	volatile tI2cRegs * const pI2c = (volatile tI2cRegs *)i2cBase->I2cHwRegs;
	UBYTE isSuccess = 1, ubIoError = I2C_OK, ubAllocError = I2C_OK;

	D(bug("  S: %08x\n", rd32le(&pI2c->S)));

	wr32le(&pI2c->A, ubAddress);
	wr32le(&pI2c->C, I2C_C_CLEAR_FIFO_ONE_SHOT);
	wr32le(&pI2c->S, I2C_S_CLKT | I2C_S_ERR | I2C_S_DONE);
	wr32le(&pI2c->DLEN, uwDataSize);
	wr32le(&pI2c->C, I2C_C_I2CEN | I2C_C_ST | I2C_C_READ_PACKET);

	UWORD uwBytesRead = 0;
	while(!(rd32le(&pI2c->S) & I2C_S_DONE)) {
		while(uwDataSize && (rd32le(&pI2c->S) & I2C_S_RXD)) {
			*(pData++) = rd32le(&pI2c->FIFO) & 0xFF;
			D(bug("  Received %02x from FIFO\n", pData[-1]));
			uwBytesRead++;
			--uwDataSize;
		}
	}

	D(bug("  Read completed. Draining FIFO\n"));

	// Transfer done, now read all pending stuff in fifo
	while(uwDataSize && (rd32le(&pI2c->S) & I2C_S_RXD)) {
		*(pData++) = rd32le(&pI2c->FIFO) & 0xFF;
		D(bug("  Received %02x from FIFO\n", pData[-1]));
		uwBytesRead++;
		--uwDataSize;
	}

	ULONG ulStatus = rd32le(&pI2c->S);
	wr32le(&pI2c->S, I2C_S_DONE);

	D(bug("  S: %08x\n", ulStatus));

	if((ulStatus & (I2C_S_ERR | I2C_S_CLKT)) || uwDataSize) {
		isSuccess = 0;
		++i2cBase->Unheard;
		ubIoError = I2C_NO_REPLY;
	}

	++i2cBase->RecvCalls;
	i2cBase->RecvBytes += uwBytesRead;

	D(bug("ReceiveI2C returns %08x\n", RESULT(isSuccess, ubIoError, ubAllocError)));

	return RESULT(isSuccess, ubIoError, ubAllocError);
}
