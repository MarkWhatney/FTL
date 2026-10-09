/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cyrillic domain detector regression harness
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "cyrillic.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void expect(const char *label, const char *domain, const bool want)
{
	const bool got = domain_contains_cyrillic(domain);
	if(got == want)
		return;

	fprintf(stderr, "FAIL %s: domain_contains_cyrillic(", label);
	if(domain == NULL)
		fprintf(stderr, "NULL");
	else
	{
		fputc('"', stderr);
		for(const unsigned char *p = (const unsigned char *)domain; *p != '\0'; p++)
		{
			if(*p >= 0x20u && *p < 0x7fu)
				fputc(*p, stderr);
			else
				fprintf(stderr, "\\x%02X", *p);
		}
		fputc('"', stderr);
	}
	fprintf(stderr, ") = %s, want %s\n", got ? "true" : "false", want ? "true" : "false");
	failures++;
}

int main(void)
{
	/* Empty and ASCII names are not Cyrillic. */
	expect("null", NULL, false);
	expect("empty", "", false);
	expect("dot", ".", false);
	expect("dots", "...", false);
	expect("ascii", "example.com", false);
	expect("short-x", "x", false);
	expect("short-xn", "xn", false);
	expect("short-xn-", "xn-", false);

	/* xn--e1afmkfd is пример. */
	expect("puny-example", "xn--e1afmkfd", true);
	expect("puny-trailing-dot", "xn--e1afmkfd.", true);
	expect("puny-uppercase", "XN--E1AFMKFD", true);
	expect("puny-mixed-case", "Xn--e1afmkfd.com", true);
	expect("puny-embedded", "www.xn--e1afmkfd.com", true);
	expect("puny-sibling-bad", "xn--bad!!!.xn--e1afmkfd.com", true);

	/* xn--ggle-55da is g + two Cyrillic o + gle. */
	expect("homograph", "xn--ggle-55da.com", true);

	/* German and Chinese IDNs, and a Latin-1 character, are not Cyrillic.
	   xn--mnchen-3ya is münchen, xn--fiqs8s is 中国, xn--tda is ü. */
	expect("german", "xn--mnchen-3ya", false);
	expect("german-fqdn", "xn--mnchen-3ya.example", false);
	expect("chinese", "xn--fiqs8s", false);
	expect("latin-u", "xn--tda", false);
	expect("malformed", "xn--bad!!!", false);
	expect("malformed-only-label", "xn--bad!!!.example.com", false);

	/* Code points around the five Cyrillic blocks, as UTF-8.
	   Hex escapes are terminated by string concatenation so a following
	   hex digit is not swallowed. */
	expect("u+0400", "\xD0\x80", true);
	expect("u+04FF", "\xD3\xBF", true);
	expect("u+03FF", "\xCF\xBF", false);
	expect("u+0500", "\xD4\x80", true);
	expect("u+052F", "\xD4\xAF", true);
	expect("u+0530", "\xD4\xB0", false);
	expect("u+2DDF", "\xE2\xB7\x9F", false);
	expect("u+2DE0", "\xE2\xB7\xA0", true);
	expect("u+2DFF", "\xE2\xB7\xBF", true);
	expect("u+A640", "\xEA\x99\x80", true);
	expect("u+A69F", "\xEA\x9A\x9F", true);
	expect("u+A6A0", "\xEA\x9A\xA0", false);
	expect("u+1C80", "\xE1\xB2\x80", true);
	expect("u+1C8F", "\xE1\xB2\x8F", true);
	expect("u+1C90", "\xE1\xB2\x90", false);

	/* Cyrillic е (U+0435) inside an otherwise ASCII label. */
	expect("raw-embedded", "ex" "\xD0\xB5" "mple.com", true);
	expect("raw-label", "www." "\xD0\xBF\xD1\x80\xD0\xB8\xD0\xBC\xD0\xB5\xD1\x80" ".com", true);

	/* Overlong encodings of Cyrillic (or of ASCII) are not matches.
	   U+0400 as a 4-byte sequence, and 'e' as a 3-byte sequence. */
	expect("overlong-u+0400", "\xF0\x81\x90\x80", false);
	expect("overlong-ascii", "\xE0\x81\xA5", false);
	expect("truncated-utf8", "\xD0", false);
	expect("bad-continuation", "\xD0\x20", false);

	if(failures != 0)
	{
		fprintf(stderr, "%d cyrillic regression failure(s)\n", failures);
		return 1;
	}

	printf("CYRILLIC_REGRESSION=PASS\n");
	return 0;
}
