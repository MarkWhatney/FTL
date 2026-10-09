/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cyrillic domain detection
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "cyrillic.h"

#include <idn2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// DNS labels are at most 63 octets (RFC 1035).
#define CYRILLIC_MAX_LABEL 63

static bool __attribute__((pure)) codepoint_is_cyrillic(const uint32_t cp)
{
	if(cp >= 0x0400u && cp <= 0x04FFu)
		return true;
	if(cp >= 0x0500u && cp <= 0x052Fu)
		return true;
	if(cp >= 0x2DE0u && cp <= 0x2DFFu)
		return true;
	if(cp >= 0xA640u && cp <= 0xA69Fu)
		return true;
	if(cp >= 0x1C80u && cp <= 0x1C8Fu)
		return true;
	return false;
}

// Return true when the UTF-8 sequence contains a Cyrillic code point.
// Invalid and overlong sequences are skipped. They are not Cyrillic.
static bool __attribute__((pure)) utf8_has_cyrillic(const unsigned char *s, const size_t len)
{
	size_t i = 0;

	while(i < len)
	{
		const unsigned char b = s[i];
		uint32_t cp;
		unsigned int need;
		bool well_formed = true;

		if(b < 0x80u)
		{
			cp = b;
			need = 1u;
		}
		else if((b & 0xE0u) == 0xC0u)
		{
			cp = (uint32_t)(b & 0x1Fu);
			need = 2u;
		}
		else if((b & 0xF0u) == 0xE0u)
		{
			cp = (uint32_t)(b & 0x0Fu);
			need = 3u;
		}
		else if((b & 0xF8u) == 0xF0u)
		{
			cp = (uint32_t)(b & 0x07u);
			need = 4u;
		}
		else
		{
			i++;
			continue;
		}

		if(i + need > len)
			return false;

		for(unsigned int k = 1u; k < need; k++)
		{
			const unsigned char cont = s[i + k];
			if((cont & 0xC0u) != 0x80u)
			{
				well_formed = false;
				break;
			}
			cp = (cp << 6) | (uint32_t)(cont & 0x3Fu);
		}
		if(!well_formed)
		{
			i++;
			continue;
		}

		// Reject overlong encodings and UTF-16 surrogates.
		if((need == 2u && cp < 0x80u) ||
		   (need == 3u && cp < 0x800u) ||
		   (need == 4u && (cp < 0x10000u || cp > 0x10FFFFu)) ||
		   (cp >= 0xD800u && cp <= 0xDFFFu))
		{
			i += need;
			continue;
		}

		if(codepoint_is_cyrillic(cp))
			return true;

		i += need;
	}

	return false;
}

static bool __attribute__((pure)) label_is_ace(const char *label, const size_t len)
{
	if(len < 4u)
		return false;

	return (label[0] == 'x' || label[0] == 'X') &&
	       (label[1] == 'n' || label[1] == 'N') &&
	       label[2] == '-' &&
	       label[3] == '-';
}

// Cheap reject for the query path: ordinary ASCII names never match.
static bool __attribute__((pure)) might_contain_cyrillic(const char *domain)
{
	const unsigned char *p = (const unsigned char *)domain;

	for(; *p != '\0'; p++)
	{
		if(*p >= 0x80u)
			return true;

		// Do not read past the terminating NUL on a short tail.
		if((*p == 'x' || *p == 'X') &&
		   p[1] != '\0' && (p[1] == 'n' || p[1] == 'N') &&
		   p[2] == '-' && p[3] == '-')
			return true;
	}

	return false;
}

static bool ace_label_is_cyrillic(const char *label, const size_t len)
{
	char ace[CYRILLIC_MAX_LABEL + 1];
	char *unicode = NULL;
	int rc;
	bool match;

	// Longer than a DNS label: not a name we can decode as punycode.
	if(len > CYRILLIC_MAX_LABEL)
		return false;

	memcpy(ace, label, len);
	ace[len] = '\0';

	// 8z8z takes and returns UTF-8. Punycode is ASCII, so this does not
	// depend on the process locale (idn2_to_unicode_lzlz does).
	rc = idn2_to_unicode_8z8z(ace, &unicode, 0);
	if(rc != IDN2_OK || unicode == NULL)
	{
		free(unicode);
		return false;
	}

	match = utf8_has_cyrillic((const unsigned char *)unicode, strlen(unicode));
	free(unicode);
	return match;
}

bool domain_contains_cyrillic(const char *domain)
{
	const char *p;
	size_t len;

	if(domain == NULL || domain[0] == '\0')
		return false;

	if(!might_contain_cyrillic(domain))
		return false;

	len = strlen(domain);
	while(len > 0u && domain[len - 1u] == '.')
		len--;
	if(len == 0u)
		return false;

	p = domain;
	while((size_t)(p - domain) < len)
	{
		const char *dot = memchr(p, '.', len - (size_t)(p - domain));
		const char *label_end = dot != NULL ? dot : domain + len;
		const size_t labellen = (size_t)(label_end - p);

		if(labellen > 0u)
		{
			if(label_is_ace(p, labellen))
			{
				if(ace_label_is_cyrillic(p, labellen))
					return true;
			}
			else if(utf8_has_cyrillic((const unsigned char *)p, labellen))
			{
				return true;
			}
		}

		if(dot == NULL)
			break;
		p = dot + 1;
	}

	return false;
}
