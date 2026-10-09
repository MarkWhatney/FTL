/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cyrillic domain detection
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CYRILLIC_H
#define CYRILLIC_H

#include <stdbool.h>

// Return true when any label of domain contains a code point in:
//   U+0400..U+04FF  Cyrillic
//   U+0500..U+052F  Cyrillic Supplement
//   U+2DE0..U+2DFF  Cyrillic Extended-A
//   U+A640..U+A69F  Cyrillic Extended-B
//   U+1C80..U+1C8F  Cyrillic Extended-C
//
// ACE labels (xn--, any case) are decoded with libidn2. Every other label is
// scanned as UTF-8, so a name that has not been normalized to punycode is
// still detected. A punycode label that does not decode is not Cyrillic.
// Trailing DNS dots are ignored. NULL and empty names are not Cyrillic.
bool domain_contains_cyrillic(const char *domain);

#endif // CYRILLIC_H
