/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define SSH_DONT_OVERLOAD_OPENSSL_FUNCS
#include "includes.h"

#ifdef WITH_OPENSSL

#include <stdarg.h>
#include <string.h>

#ifdef USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#endif

#include "log.h"

#include "openssl-compat.h"

BOOL is_tm_Initialized = 0;
TEXTMETRIC tm;

/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status
 * We match major, minor, fix and status (not patch) for <1.0.0.
 * After that, we acceptable compatible fix versions (so we
 * allow 1.0.1 to work with 1.0.0). Going backwards is only allowed
 * within a patch series.
 */

int
ssh_compatible_openssl(long headerver, long libver)
{
	long mask, hfix, lfix;

	/* exact match is always OK */
	if (headerver == libver)
		return 1;

	/* for versions < 1.0.0, major,minor,fix,status must match */
	if (headerver < 0x1000000f) {
		mask = 0xfffff00fL; /* major,minor,fix,status */
		return (headerver & mask) == (libver & mask);
	}

	/*
	 * For versions >= 1.0.0, major,minor,status must match and library
	 * fix version must be equal to or newer than the header.
	 */
	mask = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	if ( (headerver & mask) == (libver & mask) && lfix >= hfix)
		return 1;
	return 0;
}

int
get_wcwidth(wchar_t wc) {
	if (0x20 <= wc && wc <= 0x7e)
		/* ASCII */
		return 1;
	else if (0x3041 <= wc && wc <= 0x3094)
		/* Hiragana */
		return 1;
	else if (0x30a1 <= wc && wc <= 0x30f6)
		/* Katakana */
		return 2;
	else if (0x3105 <= wc && wc <= 0x312c)
		/* Bopomofo */
		return 2;
	else if (0x3131 <= wc && wc <= 0x318e)
		/* Hangul Elements */
		return 2;
	else if (0xac00 <= wc && wc <= 0xd7a3)
		/* Korean Hangul Syllables */
		return 2;
	else if (0xff01 <= wc && wc <= 0xff5e)
		/* Fullwidth ASCII variants */
		return 2;
	else if (0xff61 <= wc && wc <= 0xff9f)
		/* Halfwidth Katakana variants */
		return 1;
	else if ((0xffa0 <= wc && wc <= 0xffbe) ||
		(0xffc2 <= wc && wc <= 0xffc7) ||
		(0xffca <= wc && wc <= 0xffcf) ||
		(0xffd2 <= wc && wc <= 0xffd7) ||
		(0xffda <= wc && wc <= 0xffdc))
		/* Halfwidth Hangule variants */
		return 1;
	else if (0xffe0 <= wc && wc <= 0xffe6)
		/* Fullwidth symbol variants */
		return 2;
	else if (0x4e00 <= wc && wc <= 0x9fa5)
		/* Han Ideographic */
		return 2;
	else if (0xf900 <= wc && wc <= 0xfa2d)
		/* Han Compatibility Ideographs */
		return 2;
	else {
		/* Unknown character: need to use GDI*/
		HWND hwnd;
		HDC hDC;
		int ret = 1, width = 0;

		if ((hwnd = GetConsoleWindow()) == NULL) {
			ret = 1;
			goto done;
		}
		if ((hDC = GetDC(hwnd)) == NULL ) {
			ret = 1;
			goto done;
		}
		if (!is_tm_Initialized) {
			memset(&tm, L'\0', sizeof(tm));
			if (!GetTextMetricsW(hDC, &tm)) {
				ret = 1;
				goto done;
			}
			is_tm_Initialized = 1;
		}
		
		if (!GetCharWidth32W(hDC, (UINT)wc, (UINT)wc, &width)) {
			ret = 1;
			goto done;
		}
		if (width >= tm.tmMaxCharWidth) {
			ret = 2;
			goto done;
		}
done:
		if (hwnd != NULL && hDC != NULL)
			ReleaseDC(hwnd, hDC);
		
		return ret;
	}
}

#ifdef	USE_OPENSSL_ENGINE
void
ssh_OpenSSL_add_all_algorithms(void)
{
	OpenSSL_add_all_algorithms();

	/* Enable use of crypto hardware */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
	OPENSSL_config(NULL);
}
#endif

#endif /* WITH_OPENSSL */
