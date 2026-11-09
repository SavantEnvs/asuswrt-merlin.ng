#include <stdio.h>
#include <string.h>
#include <expat.h>

static int depth, elements, chars;

static void XMLCALL start(void *u, const XML_Char *n, const XML_Char **a) {
  (void)u;
  printf("%*s<%s", depth * 2, "", n);
  for (; *a; a += 2) printf(" %s=\"%s\"", a[0], a[1]);
  printf(">\n");
  depth++; elements++;
}
static void XMLCALL end(void *u, const XML_Char *n) { (void)u; depth--; printf("%*s</%s>\n", depth * 2, "", n); }
static void XMLCALL text(void *u, const XML_Char *s, int l) { (void)u; (void)s; chars += l; }

int main(void) {
  const char *doc =
      "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY e \"entity-text\">]>"
      "<root id=\"7\"><a k=\"v\">x&e;y</a><b/><c>&#65;&lt;</c></root>";
  XML_Parser p = XML_ParserCreate(NULL);
  XML_SetElementHandler(p, start, end);
  XML_SetCharacterDataHandler(p, text);
  if (XML_Parse(p, doc, (int)strlen(doc), 1) == XML_STATUS_ERROR) {
    printf("error=%s\n", XML_ErrorString(XML_GetErrorCode(p)));
    return 1;
  }
  XML_ParserFree(p);
  printf("elements=%d chars=%d\n", elements, chars);
  const char *bad = "<a><b></a>";
  p = XML_ParserCreate(NULL);
  if (XML_Parse(p, bad, (int)strlen(bad), 1) == XML_STATUS_OK) return 1;
  printf("mismatch=%s line=%lu\n", XML_ErrorString(XML_GetErrorCode(p)), (unsigned long)XML_GetCurrentLineNumber(p));
  XML_ParserFree(p);
  return 0;
}
