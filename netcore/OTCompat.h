/* OTCompat.h - what Open Transport 1.1's headers expect from the Universal Interfaces and Symantec C++ 7's
   "System 7.1 for ETO #13" headers do not have. Include it before <OpenTransport.h>. 68K only. */

#ifndef __OTCOMPAT__
#define __OTCOMPAT__

#include <Types.h>
#include "OTNames.h"				/* pascal OT calls under MPW's upper-case object names */

#define __MIXEDMODE__				/* no MixedMode.h here; classic 68K code needs no routine descriptors */

#ifndef GENERATING68K
#define GENERATING68K			1
#define GENERATINGPOWERPC		0
#define GENERATINGCFM			0
#endif
#ifndef PRAGMA_ALIGN_SUPPORTED
#define PRAGMA_ALIGN_SUPPORTED	0
#endif

typedef unsigned char	UInt8;
typedef signed char		SInt8;
typedef unsigned short	UInt16;
typedef short			SInt16;
typedef unsigned long	UInt32;
typedef long			SInt32;
typedef long			OSStatus;
/* UnsignedWide comes with THINK's MacHeaders (Timer.h) */

#endif
