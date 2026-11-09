#include <stddef.h>
#include <stdint.h>
#include <expat.h>

static void XMLCALL on_start(void *u, const XML_Char *n, const XML_Char **a) { (void)u; (void)n; (void)a; }
static void XMLCALL on_end(void *u, const XML_Char *n) { (void)u; (void)n; }
static void XMLCALL on_chars(void *u, const XML_Char *s, int l) { (void)u; (void)s; (void)l; }
static void XMLCALL on_pi(void *u, const XML_Char *t, const XML_Char *d) { (void)u; (void)t; (void)d; }
static void XMLCALL on_comment(void *u, const XML_Char *d) { (void)u; (void)d; }
static void XMLCALL on_default(void *u, const XML_Char *s, int l) { (void)u; (void)s; (void)l; }
static void XMLCALL on_entity_decl(void *u, const XML_Char *n, int p, const XML_Char *v, int vl,
                                   const XML_Char *b, const XML_Char *sys, const XML_Char *pub,
                                   const XML_Char *nn) {
  (void)u; (void)n; (void)p; (void)v; (void)vl; (void)b; (void)sys; (void)pub; (void)nn;
}
static int XMLCALL on_ext_entity(XML_Parser p, const XML_Char *c, const XML_Char *b,
                                 const XML_Char *s, const XML_Char *pub) {
  (void)p; (void)c; (void)b; (void)s; (void)pub;
  return XML_STATUS_OK;
}

/* byte 0: bit0 = namespace-aware, bit1 = chunked feeding, bit2 = parse parameter entities */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  uint8_t mode = data[0];
  data++; size--;

  XML_Parser p = (mode & 1) ? XML_ParserCreateNS(NULL, '|') : XML_ParserCreate(NULL);
  if (!p) return -1;
  XML_SetHashSalt(p, 0x1234);
  XML_SetElementHandler(p, on_start, on_end);
  XML_SetCharacterDataHandler(p, on_chars);
  XML_SetProcessingInstructionHandler(p, on_pi);
  XML_SetCommentHandler(p, on_comment);
  XML_SetDefaultHandler(p, on_default);
  XML_SetEntityDeclHandler(p, on_entity_decl);
  XML_SetExternalEntityRefHandler(p, on_ext_entity);
  if (mode & 4) XML_SetParamEntityParsing(p, XML_PARAM_ENTITY_PARSING_ALWAYS);

  if (mode & 2) {
    size_t i = 0;
    while (i < size) {
      size_t n = size - i < 7 ? size - i : 7;
      if (XML_Parse(p, (const char *)data + i, (int)n, 0) == XML_STATUS_ERROR) break;
      i += n;
    }
    if (i >= size) XML_Parse(p, "", 0, 1);
  } else {
    XML_Parse(p, (const char *)data, (int)size, 1);
  }
  XML_ParserFree(p);
  return 0;
}
