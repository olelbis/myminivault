//go:build darwin && cgo

package keychain

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <stdlib.h>

static OSStatus saveToken(const char *account, const void *bytes, long length) {
 CFStringRef a = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
 if (!a) return errSecParam;
 const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccount};
 const void *values[] = {kSecClassGenericPassword, CFSTR("myminivault"), a};
 CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
 for (int i = 0; i < 3; i++) CFDictionarySetValue(query, keys[i], values[i]);
 CFDataRef data = CFDataCreate(NULL, bytes, length);
 const void *updateKeys[] = {kSecValueData};
 const void *updateValues[] = {data};
 CFDictionaryRef update = CFDictionaryCreate(NULL, updateKeys, updateValues, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
 OSStatus status = SecItemUpdate(query, update);
 if (status == errSecItemNotFound) {
  CFDictionarySetValue(query, kSecValueData, data);
  status = SecItemAdd(query, NULL);
 }
 CFRelease(update); CFRelease(data); CFRelease(query); CFRelease(a);
 return status;
}
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"
)

func saveNative(account string, encoded []byte) error {
	if strings.ContainsRune(account, 0) || len(encoded) == 0 {
		return fmt.Errorf("invalid Keychain input")
	}
	a := C.CString(account)
	defer C.free(unsafe.Pointer(a))
	status := C.saveToken(a, unsafe.Pointer(&encoded[0]), C.long(len(encoded)))
	if status != 0 {
		return fmt.Errorf("keychain write failed (OSStatus %d)", int(status))
	}
	return nil
}
