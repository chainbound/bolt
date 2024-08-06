package api

import (
	"encoding/binary"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
)

// These types are taken from https://chainbound.github.io/bolt-docs/

const (
	// Note: we decided to set max constraints per slot to the same value
	// as the max transactions per block in Ethereum. This allows bolt operators
	// to decide how many commitments to include in a slot without the protocol
	// imposing hard limits that would be really hard to change in the future.
	//
	// Specs: https://github.com/ethereum/consensus-specs/blob/9515f3e7e1ce893f97ac638d0280ea9026518bad/specs/bellatrix/beacon-chain.md#execution
	MAX_CONSTRAINTS_PER_SLOT  = 1048576    // 2**20
	MAX_BYTES_PER_TRANSACTION = 1073741824 // 2**30
)

type SignedConstraints struct {
	Message *ConstraintsMessage `json:"message"`
	// NOTE: This might change to an ECDSA signature in the future. In such case,
	// when encoding/decoding SSZ we should take into account that it is 64 bytes long instead of 96
	Signature phase0.BLSSignature `ssz-size:"96" json:"signature"`
}

type ConstraintsMessage struct {
	ValidatorIndex uint64        `json:"validator_index"`
	Slot           uint64        `json:"slot"`
	Constraints    []*Constraint `ssz-max:"1048576" json:"constraints"`
}

type Constraint struct {
	Tx    Transaction `ssz-max:"1073741824" json:"tx"`
	Index *Index      `json:"index"`
}

// Index is the Union[uint64, None] (For SSZ purposes)
type Index uint64

func NewIndex(i uint64) *Index {
	idx := Index(i)
	return &idx
}

func (c SignedConstraints) String() string {
	return JSONStringify(c)
}

func (c ConstraintsMessage) String() string {
	return JSONStringify(c)
}

func (c Constraint) String() string {
	return JSONStringify(c)
}

// ConstraintsMap is a map of constraints for a block.
type ConstraintsMap = map[phase0.Hash32]*Constraint

// ConstraintCache is a cache for constraints.
type ConstraintCache struct {
	// map of slots to constraints
	constraints map[uint64]ConstraintsMap
}

func (c *SignedConstraints) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

func (c *SignedConstraints) MarshalSSZTo(dst []byte) ([]byte, error) {
	// We have 4 bytes of an offset to a dinamically sized object
	// plus 96 bytes of the BLS signature. This indicates
	// where the dynamic data begins
	offset := 100

	// Field (0) `Message`
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) `Signature`
	dst = append(dst, c.Signature[:]...)

	// Field (0) `Message`
	dst, err := c.Message.MarshalSSZTo(dst)

	return dst, err
}

func (c *SignedConstraints) SizeSSZ() int {
	// At minimum, the size is 4 bytes of an offset to a dinamically sized object
	// plus 96 bytes of the BLS signature
	size := 100

	// Field (0) 'Message'. We need to add the size of the message with its default values
	if c.Message == nil {
		c.Message = new(ConstraintsMessage)
	}
	size += c.Message.SizeSSZ()

	return 0
}

func (c *SignedConstraints) UnmarshalSSZ(buf []byte) (err error) {
	size := uint64(len(buf))
	if size < 100 {
		// The buf must be at least 100 bytes long according to offset + signature
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64 // Offset (0) 'Message'

	// Offset (0) 'Message'. Handle offset too big and too small respectively
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}
	if o0 < 100 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (0) 'Message'
	buf = tail[o0:]
	if c.Message == nil {
		c.Message = new(ConstraintsMessage)
	}
	if err = c.Message.UnmarshalSSZ(buf); err != nil {
		return
	}

	// Field (1) `Signature`
	copy(c.Signature[:], tail[4:100])

	return
}

func (m *ConstraintsMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(m)
}

func (m *ConstraintsMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	// We have 4 bytes of an offset to a dinamically sized object
	// plus 16 bytes of the two uint64 fields
	offset := 20
	dst = buf

	// Field (0) `ValidatorIndex`
	dst = ssz.MarshalUint64(dst, m.ValidatorIndex)

	// Field (1) `Slot`
	dst = ssz.MarshalUint64(dst, m.Slot)

	// Field (2) `Constraints`
	dst = ssz.WriteOffset(dst, offset)

	// ------- Dynamic fields -------

	// Field (2) `Constraints`
	if size := len(m.Constraints); size > MAX_CONSTRAINTS_PER_SLOT {
		err = ssz.ErrListTooBigFn("ConstraintsMessage.Constraints", size, MAX_CONSTRAINTS_PER_SLOT)
		return
	}
	// Each constraint is a dynamically sized object so we first add the offsets
	offset = 4 * len(m.Constraints)
	for i := 0; i < len(m.Constraints); i++ {
		dst = ssz.WriteOffset(dst, offset)
		offset += m.Constraints[i].SizeSSZ()
	}
	// Now we add the actual data
	for i := 0; i < len(m.Constraints); i++ {
		if dst, err = m.Constraints[i].MarshalSSZTo(dst); err != nil {
			return
		}
		if size := len(m.Constraints[i].Tx); size > MAX_BYTES_PER_TRANSACTION {
			err = ssz.ErrBytesLengthFn("Constraints[i].Tx", size, MAX_BYTES_PER_TRANSACTION)
			return
		}
	}

	return
}

func (m *ConstraintsMessage) SizeSSZ() int {
	// At minimum, the size is 4 bytes of an offset to a dinamically sized object
	// plus 16 bytes of the two uint64 fields
	size := 20

	// Field (2) 'Constraints'. We need to add the size of the constraints with their default values
	for i := 0; i < len(m.Constraints); i++ {
		// The offset to the transaction list
		size += 4

		size += len(m.Constraints[i].Tx)
		size += m.Constraints[i].Index.SizeSSZ()
	}
	return size
}

func (m *ConstraintsMessage) UnmarshalSSZ(buf []byte) (err error) {
	size := uint64(len(buf))
	if size < 20 {
		// 8 + 8 + 4 bytes for the offset
		return ssz.ErrSize
	}

	tail := buf
	var o2 uint64

	// Field (0) `ValidatorIndex`
	m.ValidatorIndex = binary.LittleEndian.Uint64(buf[0:8])

	// Field (1) `Slot`
	m.Slot = binary.LittleEndian.Uint64(buf[8:16])

	// Offset (2) 'Constraints'
	if o2 = ssz.ReadOffset(buf[16:20]); o2 > size {
		return ssz.ErrOffset
	}
	if o2 < 20 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) `Constraints`
	buf = tail[o2:]
	// We first read the amount of offset values we have, by looking
	// at how big is the first offset
	var length int
	if length, err = ssz.DecodeDynamicLength(buf, MAX_CONSTRAINTS_PER_SLOT); err != nil {
		return
	}
	m.Constraints = make([]*Constraint, length)
	err = ssz.UnmarshalDynamic(buf, length, func(indx int, buf []byte) (err error) {
		if m.Constraints[indx] == nil {
			m.Constraints[indx] = new(Constraint)
		}
		return m.Constraints[indx].UnmarshalSSZ(buf)
	})

	return
}

func (c *Constraint) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(c)
}

func (c *Constraint) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	// Both fields are dynamically sized, so we start with two offsets of 4 bytes each
	offset := 8
	dst = buf

	// Field (0) `Tx`
	dst = ssz.WriteOffset(dst, offset)
	offset += len(c.Tx)

	// Field (1) `Index`
	dst = ssz.WriteOffset(dst, offset)

	// Field (0) `Tx`
	dst = append(dst, c.Tx...)

	// Field (1) `Index`
	if c.Index == nil {
		dst = append(dst, 0)
	} else {
		// Index is `Union[None, uint64]
		dst = append(dst, 1)
		dst = ssz.MarshalUint64(dst, uint64(*c.Index))
	}

	return
}

func (c *Constraint) SizeSSZ() int {
	// Both fields are dynamically sized, so we start with two offsets of 4 bytes each
	size := 8

	// Field (0) 'Tx'.
	size += len(c.Tx)

	// Field (1) 'Index'.
	size += c.Index.SizeSSZ()

	return size
}

func (c *Constraint) UnmarshalSSZ(buf []byte) (err error) {
	size := uint64(len(buf))
	if size < 8 {
		// It needs to contain at least 8 bytes for the two offsets
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1 uint64

	// Offset (0) 'Tx'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}
	if o0 < 8 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Index'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Field (0) `Tx`
	buf = tail[o0:o1]
	if len(buf) > MAX_BYTES_PER_TRANSACTION {
		return ssz.ErrBytesLengthFn("Constraint.Tx", len(buf), MAX_BYTES_PER_TRANSACTION)
	}
	c.Tx = make([]byte, 0, len(buf))
	c.Tx = append(c.Tx, buf...)

	// Field (1) `Index`
	buf = tail[o1:]
	if buf[0] == 0 {
		// Means it's a None value
		c.Index = nil
	} else {
		c.Index = new(Index)
		*(c.Index) = Index(binary.LittleEndian.Uint64(buf[1:]))
	}

	return
}

func (i *Index) SizeSSZ() int {
	if i == nil {
		return 1
	}
	// selector + uint64
	return 9
}
