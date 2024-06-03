package api

import (
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/stretchr/testify/require"
)

func TestSignedConstraints_MarshalSSZTo(t *testing.T) {
	type fields struct {
		Message   *ConstraintsMessage
		Signature phase0.BLSSignature
	}
	type args struct {
		dst []byte
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	// wantDst1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00)
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	// wantDst2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")

	//	-------------------------------- SignedConstraints ---------------------------------------------------------------------------------------------------------------------------------------------------   |-------- ConstraintsMessage ----------------     | -- offsets -- | --- raw constraint data
	//	                                                                                                                                                                                                         |                                                 |               |
	//	offset  96 bytes of signature                                                                                                                                                                            |  validatorIndex   slot               offset(20) | off    off    |
	// 64000000_8b136ad4a3ce9443c1f42b29eeb79bf33c90f966671c2381ac25014d8b1dd4cc4b76731c4cd61dbd3978a9240b9a91ea0f9685c03f18372137a2b49eb0afeadd474476af3a7b84ccf76e7ed6a2973ea2b8eb972a455752f37578e365bf877df2_0200000000000000_0300000000000000_14000000_08000000_20000000_08000000170000000102030405060708090a0b0c0d0e0f00_08000000170000000102030405060708090a0b0c0d0e0f010100000000000000
	//

	wantDst, err := hex.DecodeString("640000008b136ad4a3ce9443c1f42b29eeb79bf33c90f966671c2381ac25014d8b1dd4cc4b76731c4cd61dbd3978a9240b9a91ea0f9685c03f18372137a2b49eb0afeadd474476af3a7b84ccf76e7ed6a2973ea2b8eb972a455752f37578e365bf877df20200000000000000030000000000000014000000080000002000000008000000170000000102030405060708090a0b0c0d0e0f0008000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	skBytes, err := hex.DecodeString("51815cb2c5489f8d7dc4f9889b9771334a80ccc6a82ce9c2a1ef66dc270c9708")
	require.NoError(t, err)
	sk, _ := bls.SecretKeyFromBytes(skBytes)
	require.NoError(t, err)

	message := &ConstraintsMessage{
		ValidatorIndex: 2,
		Slot:           3,
		Constraints: []*Constraint{
			{Tx: Transaction(tx1), Index: nil},
			{Tx: Transaction(tx1), Index: NewIndex(1)},
		},
	}

	// We tested this works gud below
	messsageSSZ, err := message.MarshalSSZ()
	require.NoError(t, err)

	sig := bls.Sign(sk, messsageSSZ)
	sigBytes := bls.SignatureToBytes(sig)

	type test struct {
		name    string
		fields  fields
		args    args
		wantDst []byte
		wantErr bool
	}

	tests := []test{
		{
			name: "nil and non-nil index",
			fields: fields{
				Message:   message,
				Signature: phase0.BLSSignature(sigBytes[:]),
			},
			args:    args{dst: make([]byte, 0)},
			wantDst: wantDst,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &SignedConstraints{
				Message:   tt.fields.Message,
				Signature: tt.fields.Signature,
			}
			got, err := c.MarshalSSZTo(tt.args.dst)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignedConstraints.MarshalSSZTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.wantDst) {
				t.Errorf("SignedConstraints.MarshalSSZTo() = %v, want %v", got, tt.wantDst)
			}
		})
	}
}

func TestSignedConstraints_UnmarshalSSZ(t *testing.T) {
	type fields struct {
		Message   *ConstraintsMessage
		Signature phase0.BLSSignature
	}

	type args struct {
		buf []byte
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	// wantDst1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00)
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	// wantDst2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")

	//	-------------------------------- SignedConstraints ---------------------------------------------------------------------------------------------------------------------------------------------------   |-------- ConstraintsMessage ----------------     | -- offsets -- | --- raw constraint data
	//	                                                                                                                                                                                                         |                                                 |               |
	//	offset  96 bytes of signature                                                                                                                                                                            |  validatorIndex   slot               offset(20) | off    off    |
	// 64000000_8b136ad4a3ce9443c1f42b29eeb79bf33c90f966671c2381ac25014d8b1dd4cc4b76731c4cd61dbd3978a9240b9a91ea0f9685c03f18372137a2b49eb0afeadd474476af3a7b84ccf76e7ed6a2973ea2b8eb972a455752f37578e365bf877df2_0200000000000000_0300000000000000_14000000_08000000_20000000_08000000170000000102030405060708090a0b0c0d0e0f00_08000000170000000102030405060708090a0b0c0d0e0f010100000000000000
	//

	buf, err := hex.DecodeString("640000008b136ad4a3ce9443c1f42b29eeb79bf33c90f966671c2381ac25014d8b1dd4cc4b76731c4cd61dbd3978a9240b9a91ea0f9685c03f18372137a2b49eb0afeadd474476af3a7b84ccf76e7ed6a2973ea2b8eb972a455752f37578e365bf877df20200000000000000030000000000000014000000080000002000000008000000170000000102030405060708090a0b0c0d0e0f0008000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	skBytes, err := hex.DecodeString("51815cb2c5489f8d7dc4f9889b9771334a80ccc6a82ce9c2a1ef66dc270c9708")
	require.NoError(t, err)
	sk, _ := bls.SecretKeyFromBytes(skBytes)
	require.NoError(t, err)

	message := &ConstraintsMessage{
		ValidatorIndex: 2,
		Slot:           3,
		Constraints: []*Constraint{
			{Tx: Transaction(tx1), Index: nil},
			{Tx: Transaction(tx1), Index: NewIndex(1)},
		},
	}

	// We tested this works gud below
	messsageSSZ, err := message.MarshalSSZ()
	require.NoError(t, err)

	sig := bls.Sign(sk, messsageSSZ)
	sigBytes := bls.SignatureToBytes(sig)

	type test struct {
		name    string
		fields  fields
		args    args
		wantDst []byte
		wantErr bool
	}

	tests := []test{
		{
			name: "nil and non-nil index",
			fields: fields{
				Message:   message,
				Signature: phase0.BLSSignature(sigBytes[:]),
			},
			args:    args{buf: buf},
			wantDst: make([]byte, 0),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := &SignedConstraints{
				Message:   tt.fields.Message,
				Signature: tt.fields.Signature,
			}
			actual := &SignedConstraints{}
			if err := actual.UnmarshalSSZ(tt.args.buf); (err != nil) != tt.wantErr {
				t.Errorf("SignedConstraints.UnmarshalSSZ() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("SignedConstraints.UnmarshalSSZ() = %v, want %v", actual, expected)
			}
		})
	}
}

func TestConstraintsMessage_MarshalSSZTo(t *testing.T) {
	type fields struct {
		ValidatorIndex uint64
		Slot           uint64
		Constraints    []*Constraint
	}
	type args struct {
		buf []byte
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	// wantDst1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00")
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	// wantDst2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")

	// ----------- ConstraintMessage ---------------| -- offsets -- | --- raw constraint data
	//                                              |               |
	//   validatorIndex   slot             offset   | off    off    |
	// 0x0200000000000000_0300000000000000_14000000_08000000_20000000_08000000170000000102030405060708090a0b0c0d0e0f00_08000000170000000102030405060708090a0b0c0d0e0f010100000000000000
	//

	wantDst, err := hex.DecodeString("0200000000000000030000000000000014000000080000002000000008000000170000000102030405060708090a0b0c0d0e0f0008000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	type test struct {
		name    string
		fields  fields
		args    args
		wantDst []byte
		wantErr bool
	}

	tests := []test{
		{
			name: "nil and non-nil index",
			fields: fields{
				ValidatorIndex: 2,
				Slot:           3,
				Constraints: []*Constraint{
					{Tx: Transaction(tx1), Index: nil},
					{Tx: Transaction(tx1), Index: NewIndex(1)},
				},
			},
			wantDst: wantDst,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ConstraintsMessage{
				ValidatorIndex: tt.fields.ValidatorIndex,
				Slot:           tt.fields.Slot,
				Constraints:    tt.fields.Constraints,
			}
			gotDst, err := m.MarshalSSZTo(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConstraintsMessage.MarshalSSZTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDst, tt.wantDst) {
				t.Errorf("ConstraintsMessage.MarshalSSZTo() = %v, want %v", gotDst, tt.wantDst)
			}
		})
	}
}

func TestConstraintsMessage_UnmarshalSSZ(t *testing.T) {
	type fields struct {
		ValidatorIndex uint64
		Slot           uint64
		Constraints    []*Constraint
	}
	type args struct {
		buf []byte
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	// wantDst1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00")
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	// wantDst2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")

	// ----------- ConstraintMessage ---------------| -- offsets -- | --- raw constraint data
	//                                              |               |
	//   validatorIndex   slot             offset   | off    off    |
	// 0x0200000000000000_0300000000000000_14000000_08000000_20000000_08000000170000000102030405060708090a0b0c0d0e0f00_08000000170000000102030405060708090a0b0c0d0e0f010100000000000000
	//

	buf, err := hex.DecodeString("0200000000000000030000000000000014000000080000002000000008000000170000000102030405060708090a0b0c0d0e0f0008000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	type test struct {
		name    string
		fields  fields
		args    args
		wantDst []byte
		wantErr bool
	}

	tests := []test{
		{
			name: "nil and non-nil index",
			fields: fields{
				ValidatorIndex: 2,
				Slot:           3,
				Constraints: []*Constraint{
					{Tx: Transaction(tx1), Index: nil},
					{Tx: Transaction(tx1), Index: NewIndex(1)},
				},
			},
			args:    args{buf: buf},
			wantDst: []byte{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := &ConstraintsMessage{
				ValidatorIndex: tt.fields.ValidatorIndex,
				Slot:           tt.fields.Slot,
				Constraints:    tt.fields.Constraints,
			}
			actual := &ConstraintsMessage{}
			if err := actual.UnmarshalSSZ(tt.args.buf); (err != nil) != tt.wantErr {
				t.Errorf("ConstraintsMessage.UnmarshalSSZ() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(expected, actual) {
				t.Errorf("ConstraintMessage.UnmarshalSSZ() = %v, want %v", actual, expected)
			}
		})
	}
}

func TestConstraint_MarshalSSZTo(t *testing.T) {
	type fields struct {
		Tx    Transaction
		Index *Index
	}
	type args struct {
		buf []byte
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantDst []byte
		wantErr bool
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	wantDst1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00")
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	wantDst2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	tests := []test{
		{
			name: "nil index",
			fields: fields{
				Tx:    Transaction(tx1),
				Index: nil,
			},
			args: args{
				buf: make([]byte, 0),
			},
			wantDst: wantDst1,
			wantErr: false,
		},
		{
			name: "not-nil index",
			fields: fields{
				Tx:    Transaction(tx1),
				Index: NewIndex(1),
			},
			args: args{
				buf: make([]byte, 0),
			},
			wantDst: wantDst2,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Constraint{
				Tx:    tt.fields.Tx,
				Index: tt.fields.Index,
			}
			gotDst, err := c.MarshalSSZTo(tt.args.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Constraint.MarshalSSZTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotDst, tt.wantDst) {
				t.Errorf("Constraint.MarshalSSZTo() = %v, want %v", gotDst, tt.wantDst)
			}
		})
	}
}

func TestConstraint_UnmarshalSSZ(t *testing.T) {
	type fields struct {
		Tx    Transaction
		Index *Index
	}
	type args struct {
		buf []byte
	}
	type test struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}

	tx1, err := hex.DecodeString("0102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)
	// remember that uints are in little endian!
	//    offset   offset(8+16-1=23)   tx                    none
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_00"
	buf1, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f00")
	require.NoError(t, err)
	//    offset   offset(8+16-1=23)   tx                    selector and index
	// "0x08000000_17000000_000102030405060708090a0b0c0d0e0f_010100000000000000"
	buf2, err := hex.DecodeString("08000000170000000102030405060708090a0b0c0d0e0f010100000000000000")
	require.NoError(t, err)

	tests := []test{
		{
			name: "nil index",
			fields: fields{
				Tx:    Transaction(tx1),
				Index: nil,
			},
			args: args{buf: buf1},
		},
		{
			name: "non-nil index",
			fields: fields{
				Tx:    Transaction(tx1),
				Index: NewIndex(1),
			},
			args: args{buf: buf2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := &Constraint{
				Tx:    tt.fields.Tx,
				Index: tt.fields.Index,
			}
			c := &Constraint{}
			if err := c.UnmarshalSSZ(tt.args.buf); (err != nil) != tt.wantErr {
				t.Errorf("Constraint.UnmarshalSSZ() error = %v, wantErr %v", err, tt.wantErr)
			}
			require.Equal(t, want.Tx, c.Tx)
			require.Equal(t, want.Index, c.Index)
		})
	}
}
