/**
 * From <http://cap.potazmo.cz/software/_bits_n_pieces/asn1_time_t.c>
 */
/*
 * Copyright (c) 2011 Martin Pelikan <martin.pelikan@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "sln_certs.h"
#include <time.h>
#include <openssl/ssl.h>

/* Returns the wall time in the specified time zone. */
time_t
sln_asn1_time_to_timestamp(ASN1_TIME *as)
{
#define B2I(byte)	((byte) - '0')
/* offset from GMT has to be in seconds - format +HHMM */
#define OFFSET_SEC(str, i)	(			\
	((B2I(str[i+1]) * 10 + B2I(str[i+2])) * 3600)	\
	+ ((B2I(str[i+3]) * 10 + B2I(str[i+4])) * 60) )
	
	int i;
	char *data = (char *)as->data;
	struct tm tm;
	time_t current;

	memset(&tm, 0, sizeof(tm));

	switch (as->type) {
	/* YYMMDDHHMM[SS]{Z,{+,-}hhmm} */
	case V_ASN1_UTCTIME:
		/* first part basic check */
		if (as->length < 11)
			return (-1);
		for (i = 0; i < 10; ++i)
			if (data[i] < '0' || data[i] > '9')
				return (-1);

		/* year - 1900 is OK for mktime() */
		tm.tm_year = B2I(data[0]) * 10 + B2I(data[1]);
		if (tm.tm_year < 50)
			tm.tm_year += 100;

		/* month has to be -1 for mktime() */
		tm.tm_mon = B2I(data[2]) * 10 + B2I(data[3]) - 1;
		if (tm.tm_mon >= 12 || tm.tm_mon < 0)
			return (-1);

		/* day */
		tm.tm_mday = B2I(data[4]) * 10 + B2I(data[5]);
		if (tm.tm_mday > 31 || tm.tm_mday < 1)
			return (-1);

		/* hour */
		tm.tm_hour = B2I(data[6]) * 10 + B2I(data[7]);
		if (tm.tm_hour > 23 || tm.tm_hour < 0)
			return (-1);

		/* minute */
		tm.tm_min = B2I(data[8]) * 10 + B2I(data[9]);
		if (tm.tm_min > 59 || tm.tm_min < 0)
			return (-1);

		if (as->length > 11) {
			switch (data[12]) {
			/* These three cases have seconds specified. */
			case 'Z':
				break;
			/* yymmddhhmmss+HHMM */
			case '+':
				tm.tm_gmtoff = OFFSET_SEC(data, 12);
				break;
			case '-':
				tm.tm_gmtoff = -OFFSET_SEC(data, 12);
				break;
			/*
			 * Here is either a number, which would be
			 * part of the offset from GMT, or it's an
			 * error. We won't have to parse seconds.
			 */
			default:
				if (data[12] < '0' || data[12] > '9')
					return (-1);
				/* yymmddhhmm+HHMM */
				else if (data[10] == '+')
					tm.tm_gmtoff = OFFSET_SEC(data, 10);
				else if (data[10] == '-')
					tm.tm_gmtoff = -OFFSET_SEC(data, 10);
				goto convert;
			}

			/* seconds for those three cases */
			tm.tm_sec = B2I(data[10]) * 10 + B2I(data[11]);
			if (tm.tm_sec > 59 || tm.tm_sec < 0)
				return (-1);
		}
		else if (data[10] != 'Z')
			return (-1);
		break;

	/* YYYYMMDDHHMM[SS[.F[F[F[F[F[F[F...]]]]]]]]{Z,{+,-}hhmm} */
	case V_ASN1_GENERALIZEDTIME:
		if (as->length < 12)
			return (-1);
		for (i = 0; i < 12; ++i)
			if (data[i] < '0' || data[i] > '9')
				return (-1);

		/* year for mktime() */
		tm.tm_year = B2I(data[0]) * 1000 + B2I(data[1]) * 100;
		tm.tm_year += B2I(data[2]) * 10 + B2I(data[3]);
		tm.tm_year -= 1900;

		/* month for mktime() */
		tm.tm_mon = B2I(data[4]) * 10 + B2I(data[5]) - 1;
		if (tm.tm_mon >= 12 || tm.tm_mon < 0)
			return (-1);

		/* day */
		tm.tm_mday = B2I(data[6]) * 10 + B2I(data[7]);
		if (tm.tm_mday > 31 || tm.tm_mday < 1)
			return (-1);

		/* hour */
		tm.tm_hour = B2I(data[8]) * 10 + B2I(data[9]);
		if (tm.tm_hour > 23 || tm.tm_hour < 0)
			return (-1);

		/* minute */
		tm.tm_min = B2I(data[10]) * 10 + B2I(data[11]);
		if (tm.tm_min > 59 || tm.tm_min < 0)
			return (-1);

		if (as->length > 13) {
			switch (data[14]) {
			case '.':
				/*
				 * Here's an arbitrary amount of jiffies
				 * less than second - skip over them to 
				 * the timezone spec.
				 */
				for (i = 15; data[i] >= '0' && data[i] <= '9';
				    ++i) 
					;
				switch (data[i]) {
				/* yyyymmddhhmmss.fffffffffffZ */
				case 'Z':
					break;
				/* yyyymmddhhmmss.fffffffffff+HHMM */
				case '+':
					tm.tm_gmtoff = OFFSET_SEC(data, i);
					break;
				case '-':
					tm.tm_gmtoff = -OFFSET_SEC(data, i);
					break;
				default:
					return (-1);
				}
				break;
			/* yyyymmddhhmmssZ */
			case 'Z':
				break;
			/* yyyymmddhhmmss+HHMM */
			case '+':
				tm.tm_gmtoff = OFFSET_SEC(data, 14);
				break;
			case '-':
				tm.tm_gmtoff = -OFFSET_SEC(data, 14);
				break;
			/* yyyymmddhhmm+HHMM */
			default:
				if (data[14] < '0' || data[14] > '9')
					return (-1);
				else if (data[12] == '+')
					tm.tm_gmtoff = OFFSET_SEC(data, 12);
				else if (data[12] == '-')
					tm.tm_gmtoff = -OFFSET_SEC(data, 12);
				goto convert;
			}
			/* seconds for cases with jiffies, ssZ or ss+OFF */
			tm.tm_sec = B2I(data[12]) * 10 + B2I(data[13]);
			if (tm.tm_sec > 59 || tm.tm_sec < 0)
				return (-1);
		}
		else if (data[12] != 'Z')
			return (-1);
		break;
	default:
		return (-1);
	}

convert:
	/* 
	 * Convert the filled 'struct tm' and correct from the local time zone
	 * so the result is in what user proposed.
	 * Don't try to baffle mktime() with tm_gmtoff - doesn't work.
	 */
	current = time(NULL);
	i = (int) (tm.tm_gmtoff + localtime(&current)->tm_gmtoff);
	tm.tm_gmtoff = 0;
	return (time_t)(mktime(&tm) + i);

#undef B2I
#undef OFFSET_SEC
}
