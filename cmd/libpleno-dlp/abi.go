//go:build cgo

package main

/*
#include <stdlib.h>
*/
import "C"

import "unsafe"

func cstr(b []byte) *C.char { return C.CString(string(b)) }

//export pleno_dlp_version
func pleno_dlp_version() *C.char { return cstr(version()) }

//export pleno_dlp_detectors
func pleno_dlp_detectors() *C.char { return cstr(listDetectors()) }

//export pleno_dlp_scan_bytes
func pleno_dlp_scan_bytes(data *C.char, n C.longlong, opts *C.char) *C.char {
	var buf []byte
	if data != nil && n > 0 {
		buf = C.GoBytes(unsafe.Pointer(data), C.int(n))
	}
	return cstr(scanBytes(buf, C.GoString(opts)))
}

//export pleno_dlp_scan_paths
func pleno_dlp_scan_paths(paths, opts *C.char) *C.char {
	return cstr(scanPaths(C.GoString(paths), C.GoString(opts)))
}

//export pleno_dlp_verify
func pleno_dlp_verify(detector, secret *C.char) *C.char {
	return cstr(verify(C.GoString(detector), C.GoString(secret)))
}

//export pleno_dlp_revoke
func pleno_dlp_revoke(detector, secret, opts *C.char) *C.char {
	return cstr(revoke(C.GoString(detector), C.GoString(secret), C.GoString(opts)))
}

//export pleno_dlp_free
func pleno_dlp_free(p *C.char) { C.free(unsafe.Pointer(p)) }
