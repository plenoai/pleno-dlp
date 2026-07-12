//go:build opf_native

package opfnative

// #cgo CFLAGS: -I${SRCDIR}/cdeps/include
// #include <stdlib.h>
// #include "pf.h"
import "C"
