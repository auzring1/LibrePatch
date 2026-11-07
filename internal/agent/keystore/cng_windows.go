//go:build windows

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

const (
	providerPlatform = "Microsoft Platform Crypto Provider" // TPM 2.0
	providerSoftware = "Microsoft Software Key Storage Provider"

	flagMachineKey   = 0x00000020 // NCRYPT_MACHINE_KEY_FLAG
	flagSilent       = 0x00000040 // NCRYPT_SILENT_FLAG
	flagOverwriteKey = 0x00000080 // NCRYPT_OVERWRITE_KEY_FLAG
	flagPersist      = 0x80000000 // NCRYPT_PERSIST_FLAG

	propExportPolicy = "Export Policy"
	propKeyUsage     = "Key Usage"
	allowSigning     = 0x00000002 // NCRYPT_ALLOW_SIGNING_FLAG

	algECDSAP256         = "ECDSA_P256"
	blobECCPublic        = "ECCPUBLICBLOB"
	magicECDSAP256Public = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")

	nteBadKeyset = 0x80090016 // NTE_BAD_KEYSET: key does not exist
	nteNotFound  = 0x80090011 // NTE_NOT_FOUND
)

// CNG stores keys as non-exportable machine keys in Windows CNG.
type CNG struct{}

// Default returns the platform provider (the data dir is unused on Windows).
func Default(string) Provider { return &CNG{} }

var providers = []struct{ name, label string }{
	{providerPlatform, "tpm"},
	{providerSoftware, "software"},
}

func ncryptErr(op string, r uintptr) error {
	if r == 0 {
		return nil
	}
	return fmt.Errorf("%s: NCrypt status 0x%08x", op, uint32(r)) // #nosec G115 -- SECURITY_STATUS is a 32-bit value
}

func openProvider(name string) (uintptr, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(p)), 0)
	return h, ncryptErr("NCryptOpenStorageProvider", r)
}

func freeObject(h uintptr) {
	if h != 0 {
		_, _, _ = procFreeObject.Call(h)
	}
}

// Create implements Provider: TPM first, software KSP as fallback.
func (c *CNG) Create(name string) (crypto.Signer, string, error) {
	var errs []error
	for _, p := range providers {
		hp, err := openProvider(p.name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		k, err := createKey(hp, name, p.label == "software")
		if err != nil {
			freeObject(hp)
			errs = append(errs, fmt.Errorf("%s: %w", p.label, err))
			continue
		}
		return k, p.label, nil
	}
	return nil, "", errors.Join(errs...)
}

func createKey(hp uintptr, name string, software bool) (*cngKey, error) {
	alg, _ := windows.UTF16PtrFromString(algECDSAP256)
	kn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var hk uintptr
	r, _, _ := procCreatePersistedKey.Call(hp, uintptr(unsafe.Pointer(&hk)), uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(kn)), 0, flagMachineKey|flagOverwriteKey)
	if err := ncryptErr("NCryptCreatePersistedKey", r); err != nil {
		return nil, err
	}
	if software {
		// Explicitly non-exportable (the default, but never rely on defaults here).
		if err := setDWORD(hk, propExportPolicy, 0); err != nil {
			freeObject(hk)
			return nil, err
		}
	}
	if err := setDWORD(hk, propKeyUsage, allowSigning); err != nil {
		freeObject(hk)
		return nil, err
	}
	r, _, _ = procFinalizeKey.Call(hk, flagSilent)
	if err := ncryptErr("NCryptFinalizeKey", r); err != nil {
		freeObject(hk)
		return nil, err
	}
	return newCNGKey(hp, hk)
}

func setDWORD(hk uintptr, prop string, v uint32) error {
	p, _ := windows.UTF16PtrFromString(prop)
	r, _, _ := procSetProperty.Call(hk, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&v)), 4, flagPersist|flagSilent)
	return ncryptErr("NCryptSetProperty("+prop+")", r)
}

// Open implements Provider.
func (c *CNG) Open(name string) (crypto.Signer, error) {
	kn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		hp, err := openProvider(p.name)
		if err != nil {
			continue
		}
		var hk uintptr
		r, _, _ := procOpenKey.Call(hp, uintptr(unsafe.Pointer(&hk)), uintptr(unsafe.Pointer(kn)), 0, flagMachineKey|flagSilent)
		if r == 0 {
			k, err := newCNGKey(hp, hk)
			if err != nil {
				freeObject(hk)
				freeObject(hp)
				return nil, err
			}
			return k, nil
		}
		freeObject(hp)
		if uint32(r) != nteBadKeyset && uint32(r) != nteNotFound { // #nosec G115 -- SECURITY_STATUS is a 32-bit value
			return nil, ncryptErr("NCryptOpenKey", r)
		}
	}
	return nil, ErrNotFound
}

// Delete implements Provider.
func (c *CNG) Delete(name string) error {
	s, err := c.Open(name)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	k := s.(*cngKey)
	r, _, _ := procDeleteKey.Call(k.hk, 0) // also frees the key handle
	k.hk = 0
	freeObject(k.hp)
	return ncryptErr("NCryptDeleteKey", r)
}

// cngKey is a crypto.Signer backed by an NCrypt key handle.
type cngKey struct {
	mu  sync.Mutex
	hp  uintptr
	hk  uintptr
	pub *ecdsa.PublicKey
}

func newCNGKey(hp, hk uintptr) (*cngKey, error) {
	pub, err := exportPublic(hk)
	if err != nil {
		return nil, err
	}
	return &cngKey{hp: hp, hk: hk, pub: pub}, nil
}

func exportPublic(hk uintptr) (*ecdsa.PublicKey, error) {
	bt, _ := windows.UTF16PtrFromString(blobECCPublic)
	var size uint32
	r, _, _ := procExportKey.Call(hk, 0, uintptr(unsafe.Pointer(bt)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), flagSilent)
	if err := ncryptErr("NCryptExportKey(size)", r); err != nil {
		return nil, err
	}
	if size < 8 || size > 1024 {
		return nil, errors.New("unexpected public key blob size")
	}
	buf := make([]byte, size)
	r, _, _ = procExportKey.Call(hk, 0, uintptr(unsafe.Pointer(bt)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
		uintptr(unsafe.Pointer(&size)), flagSilent)
	if err := ncryptErr("NCryptExportKey", r); err != nil {
		return nil, err
	}
	// BCRYPT_ECCKEY_BLOB { ULONG dwMagic; ULONG cbKey; } followed by X || Y.
	magic := binary.LittleEndian.Uint32(buf[0:4])
	cb := int(binary.LittleEndian.Uint32(buf[4:8]))
	if magic != magicECDSAP256Public || cb != 32 || len(buf) < 8+2*cb {
		return nil, errors.New("public key is not ECDSA P-256")
	}
	// Uncompressed SEC 1 point; ParseUncompressedPublicKey also checks it is on the curve.
	point := append([]byte{4}, buf[8:8+2*cb]...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("invalid public key from CNG: %w", err)
	}
	return pub, nil
}

// Public implements crypto.Signer.
func (k *cngKey) Public() crypto.PublicKey { return k.pub }

// Sign implements crypto.Signer: digest is pre-hashed by the caller (TLS).
func (k *cngKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var size uint32
	r, _, _ := procSignHash.Call(k.hk, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0,
		uintptr(unsafe.Pointer(&size)), flagSilent)
	if err := ncryptErr("NCryptSignHash(size)", r); err != nil {
		return nil, err
	}
	if size != 64 {
		return nil, fmt.Errorf("unexpected ECDSA signature size %d", size)
	}
	sig := make([]byte, size)
	r, _, _ = procSignHash.Call(k.hk, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), flagSilent)
	if err := ncryptErr("NCryptSignHash", r); err != nil {
		return nil, err
	}
	// NCrypt returns r || s; Go/TLS expect ASN.1 DER.
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(sig[:32]))
		b.AddASN1BigInt(new(big.Int).SetBytes(sig[32:64]))
	})
	return b.Bytes()
}
