// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package zip provides support for reading and writing password protected ZIP archives.

See: http://www.pkware.com/documents/casestudies/APPNOTE.TXT

This package does not support disk spanning.

A note about ZIP64:

To be backwards compatible the FileHeader has both 32 and 64 bit Size
fields. The 64 bit fields will always contain the correct value and
for normal archives both fields will be the same. For files requiring
the ZIP64 format the 32 bit fields will be 0xffffffff and the 64 bit
fields must be used instead.

Can read/write password protected files that use Winzip's AES encryption method.
See: http://www.winzip.com/aes_info.htm
*/
package zip

import (
	"os"
	"path"
	"time"
)

// Compression methods.
const (
	Store   uint16 = 0
	Deflate uint16 = 8
)

const (
	fileHeaderSignature      = 0x04034b50
	directoryHeaderSignature = 0x02014b50
	directoryEndSignature    = 0x06054b50
	directory64LocSignature  = 0x07064b50
	directory64EndSignature  = 0x06064b50
	dataDescriptorSignature  = 0x08074b50 // de-facto standard; required by OS X Finder
	fileHeaderLen            = 30         // + filename + extra
	directoryHeaderLen       = 46         // + filename + extra + comment
	directoryEndLen          = 22         // + comment
	dataDescriptorLen        = 16         // four uint32: descriptor signature, crc32, compressed size, size
	dataDescriptor64Len      = 24         // descriptor with 8 byte sizes
	directory64LocLen        = 20         //
	directory64EndLen        = 56         // + extra

	// Constants for the first byte in CreatorVersion
	creatorFAT    = 0
	creatorUnix   = 3
	creatorNTFS   = 11
	creatorVFAT   = 14
	creatorMacOSX = 19

	// version numbers
	zipVersion20 = 20 // 2.0
	zipVersion45 = 45 // 4.5 (reads and writes zip64 archives)

	// limits for non zip64 files
	uint16max = (1 << 16) - 1
	uint32max = (1 << 32) - 1

	// extra header id's
	zip64ExtraID     = 0x0001 // zip64 Extended Information Extra Field
	winzipAesExtraID = 0x9901 // winzip AES Extra Field
)

// FileHeader describes a file within a zip file.
// See the zip spec for details.
type FileHeader struct {
	// Name is the name of the file.
	// It must be a relative path: it must not start with a drive
	// letter (e.g. C:) or leading slash, and only forward slashes
	// are allowed.
	Name string

	CreatorVersion     uint16
	ReaderVersion      uint16
	Flags              uint16
	Method             uint16
	ModifiedTime       uint16 // MS-DOS time
	ModifiedDate       uint16 // MS-DOS date
	CRC32              uint32
	CompressedSize     uint32 // Deprecated: Use CompressedSize64 instead.
	UncompressedSize   uint32 // Deprecated: Use UncompressedSize64 instead.
	CompressedSize64   uint64
	UncompressedSize64 uint64
	Extra              []byte
	ExternalAttrs      uint32 // Meaning depends on CreatorVersion
	Comment            string

	// DeferAuth being set to true will delay hmac auth/integrity
	// checks when decrypting a file meaning the reader will be
	// getting unauthenticated plaintext. It is recommended to leave
	// this set to false. For more detail:
	// https://www.imperialviolet.org/2014/06/27/streamingencryption.html
	// https://www.imperialviolet.org/2015/05/16/aeads.html
	DeferAuth bool

	encryption  EncryptionMethod
	password    passwordFn // Returns the password to use when reading/writing
	ae          uint16
	aesStrength byte
}

// FileInfo returns an os.FileInfo for the FileHeader.
func (fh *FileHeader) FileInfo() os.FileInfo {
	return headerFileInfo{fh}
}

// headerFileInfo implements os.FileInfo.
type headerFileInfo struct {
	fh *FileHeader
}

func (fi headerFileInfo) Name() string { return path.Base(fi.fh.Name) }
func (fi headerFileInfo) Size() int64 {
	if fi.fh.UncompressedSize64 > 0 {
		return int64(fi.fh.UncompressedSize64)
	}
	return int64(fi.fh.UncompressedSize)
}
func (fi headerFileInfo) IsDir() bool        { return fi.Mode().IsDir() }
func (fi headerFileInfo) ModTime() time.Time { return fi.fh.ModTime() }
func (fi headerFileInfo) Mode() os.FileMode  { return fi.fh.Mode() }
func (fi headerFileInfo) Sys() interface{}   { return fi.fh }

// FileInfoHeader creates a partially-populated FileHeader from an
// os.FileInfo.
// Because os.FileInfo's Name method returns only the base name of
// the file it describes, it may be necessary to modify the Name field
// of the returned header to provide the full path name of the file.
func FileInfoHeader(fi os.FileInfo) (*FileHeader, error) {
	size := fi.Size()
	fh := &FileHeader{
		Name:               fi.Name(),
		UncompressedSize64: uint64(size),
	}
	fh.SetModTime(fi.ModTime())
	fh.SetMode(fi.Mode())
	if fh.UncompressedSize64 > uint32max {
		fh.UncompressedSize = uint32max
	} else {
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}
	return fh, nil
}

type directoryEnd struct {
	diskNbr            uint32 // unused
	dirDiskNbr         uint32 // unused
	dirRecordsThisDisk uint64 // unused
	directoryRecords   uint64
	directorySize      uint64
	directoryOffset    uint64 // relative to file
	commentLen         uint16
	comment            string
}

// msDosTimeToTime converts an MS-DOS date and time into a time.Time.
// The resolution is 2s.
// See: http://msdn.microsoft.com/en-us/library/ms724247(v=VS.85).aspx
func msDosTimeToTime(dosDate, dosTime uint16) time.Time {
	return time.Date(
		// date bits 0-4: day of month; 5-8: month; 9-15: years since 1980
		int(dosDate>>9+1980),
		time.Month(dosDate>>5&0xf),
		int(dosDate&0x1f),

		// time bits 0-4: second/2; 5-10: minute; 11-15: hour
		int(dosTime>>11),
		int(dosTime>>5&0x3f),
		int(dosTime&0x1f*2),
		0, // nanoseconds

		time.UTC,
	)
}

// timeToMsDosTime converts a time.Time to an MS-DOS date and time.
// The resolution is 2s.
// See: http://msdn.microsoft.com/en-us/library/ms724274(v=VS.85).aspx
func timeToMsDosTime(t time.Time) (fDate uint16, fTime uint16) {
	t = t.In(time.UTC)
	fDate = uint16(t.Day() + int(t.Month())<<5 + (t.Year()-1980)<<9)
	fTime = uint16(t.Second()/2 + t.Minute()<<5 + t.Hour()<<11)
	return
}

// ModTime returns the modification time in UTC.
// The resolution is 2s.
func (fh *FileHeader) ModTime() time.Time {
	return msDosTimeToTime(fh.ModifiedDate, fh.ModifiedTime)
}

// SetModTime sets the ModifiedTime and ModifiedDate fields to the given time in UTC.
// The resolution is 2s.
func (fh *FileHeader) SetModTime(t time.Time) {
	fh.ModifiedDate, fh.ModifiedTime = timeToMsDosTime(t)
}

const (
	// Unix constants. The specification doesn't mention them,
	// but these seem to be the values agreed on by tools.
	sIFMT   = 0xf000
	sIFSOCK = 0xc000
	sIFLNK  = 0xa000
	sIFREG  = 0x8000
	sIFBLK  = 0x6000
	sIFDIR  = 0x4000
	sIFCHR  = 0x2000
	sIFIFO  = 0x1000
	sISUID  = 0x800
	sISGID  = 0x400
	sISVTX  = 0x200

	msdosDir      = 0x10
	msdosReadOnly = 0x01
)

// Mode returns the permission and mode bits for the FileHeader.
func (fh *FileHeader) Mode() (mode os.FileMode) {
	switch fh.CreatorVersion >> 8 {
	case creatorUnix, creatorMacOSX:
		mode = unixModeToFileMode(fh.ExternalAttrs >> 16)
	case creatorNTFS, creatorVFAT, creatorFAT:
		mode = msdosModeToFileMode(fh.ExternalAttrs)
	}
	if len(fh.Name) > 0 && fh.Name[len(fh.Name)-1] == '/' {
		mode |= os.ModeDir
	}
	return mode
}

// SetMode changes the permission and mode bits for the FileHeader.
func (fh *FileHeader) SetMode(mode os.FileMode) {
	fh.CreatorVersion = fh.CreatorVersion&0xff | creatorUnix<<8
	fh.ExternalAttrs = fileModeToUnixMode(mode) << 16

	// set MSDOS attributes too, as the original zip does.
	if mode&os.ModeDir != 0 {
		fh.ExternalAttrs |= msdosDir
	}
	if mode&0200 == 0 {
		fh.ExternalAttrs |= msdosReadOnly
	}
}

// isZip64 reports whether the file size exceeds the 32 bit limit
func (fh *FileHeader) isZip64() bool {
	return fh.CompressedSize64 > uint32max || fh.UncompressedSize64 > uint32max
}

func msdosModeToFileMode(m uint32) (mode os.FileMode) {
	if m&msdosDir != 0 {
		mode = os.ModeDir | 0777
	} else {
		mode = 0666
	}
	if m&msdosReadOnly != 0 {
		mode &^= 0222
	}
	return mode
}

func fileModeToUnixMode(mode os.FileMode) uint32 {
	var m uint32
	switch mode & os.ModeType {
	default:
		m = sIFREG
	case os.ModeDir:
		m = sIFDIR
	case os.ModeSymlink:
		m = sIFLNK
	case os.ModeNamedPipe:
		m = sIFIFO
	case os.ModeSocket:
		m = sIFSOCK
	case os.ModeDevice:
		if mode&os.ModeCharDevice != 0 {
			m = sIFCHR
		} else {
			m = sIFBLK
		}
	}
	if mode&os.ModeSetuid != 0 {
		m |= sISUID
	}
	if mode&os.ModeSetgid != 0 {
		m |= sISGID
	}
	if mode&os.ModeSticky != 0 {
		m |= sISVTX
	}
	return m | uint32(mode&0777)
}

func unixModeToFileMode(m uint32) os.FileMode {
	mode := os.FileMode(m & 0777)
	switch m & sIFMT {
	case sIFBLK:
		mode |= os.ModeDevice
	case sIFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case sIFDIR:
		mode |= os.ModeDir
	case sIFIFO:
		mode |= os.ModeNamedPipe
	case sIFLNK:
		mode |= os.ModeSymlink
	case sIFREG:
		// nothing to do
	case sIFSOCK:
		mode |= os.ModeSocket
	}
	if m&sISGID != 0 {
		mode |= os.ModeSetgid
	}
	if m&sISUID != 0 {
		mode |= os.ModeSetuid
	}
	if m&sISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}
