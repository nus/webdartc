// Single source of truth for the symbol-export attribute used by every
// `webdartc_*` C wrapper. Each wrapper TU is compiled with
// `-fvisibility=hidden`; only the functions explicitly tagged
// `WEBDARTC_API` end up in the resulting dylib's dynamic symbol table.

#ifndef WEBDARTC_EXPORT_H
#define WEBDARTC_EXPORT_H

#define WEBDARTC_API __attribute__((visibility("default")))

#endif // WEBDARTC_EXPORT_H
