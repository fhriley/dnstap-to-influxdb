// Package unbound implements a wrapper for libunbound(3).
// Unbound is a DNSSEC aware resolver, see https://unbound.net/
// for more information. It's up to the caller to configure
// Unbound with trust anchors. With these anchors a DNSSEC
// answer can be validated.
//
// The method's documentation can be found in libunbound(3).
// The names of the methods are in sync with the
// names used in unbound, but the underscores are removed and they
// are in camel-case, e.g. ub_ctx_resolv_conf becomes u.ResolvConf.
// Except for ub_ctx_create() and ub_ctx_delete(),
// which become: New() and Destroy() to be more in line with the standard
// Go practice.
//
// Basic use pattern:
//	u := unbound.New()
//	defer u.Destroy()
//	u.ResolvConf("/etc/resolv.conf")
//	u.AddTaFile("trustanchor")
//	r, e := u.Resolve("miek.nl.", dns.TypeA, dns.ClassINET)
//
// The asynchronous functions are implemented using goroutines. This
// means the following functions are not useful in Go and therefor
// not implemented: ub_fd, ub_wait, ub_poll, ub_process and ub_cancel.
//
// Unbound's ub_result (named Result in the package) has been modified.
// An extra field has been added, 'Rr', which is a []dns.RR.
//
// The Lookup* functions of the net package are re-implemented in this package.
package main

/*
#cgo LDFLAGS: -lunbound -lssl -lprotobuf-c -lfstrm -levent -lcrypto
#include <stdlib.h>
#include <stdio.h>
#include <unbound.h>

#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

int    array_elem_int(int *l, int i)    { return l[i]; }
char * array_elem_char(char **l, int i) { if (l == NULL) return NULL; return l[i]; }
char * new_char_pointer()               { char *p = NULL; return p; }
struct ub_result *new_ub_result() {
	struct ub_result *r;
	r = calloc(sizeof(struct ub_result), 1);
	return r;
}
int    ub_ttl(struct ub_result *r) {
	int *p;
	// Go to why_bogus add the pointer and then we will find the ttl, hopefully.
	p = (int*) ((char*)r + offsetof(struct ub_result, why_bogus) + sizeof(char*));
	return (int)*p;
}
*/
import "C"

import (
	"os"
	"strconv"
	"strings"
	"unsafe"
)

type Unbound struct {
	ctx     *C.struct_ub_ctx
	version [3]int
}

// UnboundError is an error returned from Unbound, it wraps both the
// return code and the error string as returned by ub_strerror.
type UnboundError struct {
	Err  string
	code int
}

func (e *UnboundError) Error() string {
	return e.Err
}

func newError(i int) error {
	if i == 0 {
		return nil
	}
	e := new(UnboundError)
	e.Err = errorString(i)
	e.code = i
	return e
}

func errorString(i int) string {
	return C.GoString(C.ub_strerror(C.int(i)))
}

// New wraps Unbound's ub_ctx_create.
func NewUnbound() *Unbound {
	u := new(Unbound)
	u.ctx = C.ub_ctx_create()
	u.version = u.Version()
	return u
}

// Destroy wraps Unbound's ub_ctx_delete.
func (u *Unbound) Destroy() {
	C.ub_ctx_delete(u.ctx)
}

// ZoneAdd wraps Unbound's ub_ctx_zone_add.
func (u *Unbound) ZoneAdd(zone_name, zone_type string) error {
	czone_name := C.CString(zone_name)
	defer C.free(unsafe.Pointer(czone_name))
	czone_type := C.CString(zone_type)
	defer C.free(unsafe.Pointer(czone_type))
	i := C.ub_ctx_zone_add(u.ctx, czone_name, czone_type)
	return newError(int(i))
}

// ZoneRemove wraps Unbound's ub_ctx_zone_remove.
func (u *Unbound) ZoneRemove(zone_name string) error {
	czone_name := C.CString(zone_name)
	defer C.free(unsafe.Pointer(czone_name))
	i := C.ub_ctx_zone_remove(u.ctx, czone_name)
	return newError(int(i))
}

// DataAdd wraps Unbound's ub_ctx_data_add.
func (u *Unbound) DataAdd(data string) error {
	cdata := C.CString(data)
	defer C.free(unsafe.Pointer(cdata))
	i := C.ub_ctx_data_add(u.ctx, cdata)
	return newError(int(i))
}

// DataRemove wraps Unbound's ub_ctx_data_remove.
func (u *Unbound) DataRemove(data string) error {
	cdata := C.CString(data)
	defer C.free(unsafe.Pointer(cdata))
	i := C.ub_ctx_data_remove(u.ctx, cdata)
	return newError(int(i))
}

// DebugOut wraps Unbound's ub_ctx_debugout.
func (u *Unbound) DebugOut(out *os.File) error {
	cmode := C.CString("a+")
	defer C.free(unsafe.Pointer(cmode))
	file := C.fdopen(C.int(out.Fd()), cmode)
	i := C.ub_ctx_debugout(u.ctx, unsafe.Pointer(file))
	return newError(int(i))
}

// DebugLevel wraps Unbound's ub_ctx_data_level.
func (u *Unbound) DebugLevel(d int) error {
	i := C.ub_ctx_debuglevel(u.ctx, C.int(d))
	return newError(int(i))
}

// Version wrap Ubounds's ub_version. Return the version of the Unbound
// library in as integers [major, minor, patch]
func (u *Unbound) Version() (version [3]int) {
	// split the string on the dots
	v := strings.SplitN(C.GoString(C.ub_version()), ".", 3)
	if len(v) != 3 {
		return
	}
	version[0], _ = strconv.Atoi(v[0])
	version[1], _ = strconv.Atoi(v[1])
	version[2], _ = strconv.Atoi(v[2])
	return
}
