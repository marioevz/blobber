package p2p

import (
	"bytes"

	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/codec"
	fastssz "github.com/prysmaticlabs/fastssz"
)

type Marshaler interface {
	fastssz.Marshaler
	fastssz.Unmarshaler
}

type wrappedSpecObjectEncoder struct {
	common.SpecObj
	*common.Spec
}

func WrapSpecObject(spec *common.Spec, specObj common.SpecObj) Marshaler {
	return &wrappedSpecObjectEncoder{
		SpecObj: specObj,
		Spec:    spec,
	}
}

func (w *wrappedSpecObjectEncoder) MarshalSSZTo(dst []byte) ([]byte, error) {
	marshalledObj, err := w.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return append(dst, marshalledObj...), nil
}

func (w *wrappedSpecObjectEncoder) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	if err := w.Serialize(w.Spec, codec.NewEncodingWriter(&buf)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (w *wrappedSpecObjectEncoder) SizeSSZ() int {
	return int(w.SpecObj.ByteLength(w.Spec))
}

func (w *wrappedSpecObjectEncoder) UnmarshalSSZ(b []byte) error {
	return w.Deserialize(w.Spec, codec.NewDecodingReader(bytes.NewReader(b), uint64(len(b))))
}

type wrappedSSZObjectEncoder struct {
	common.SSZObj
}

func WrapSSZObject(sszObj common.SSZObj) Marshaler {
	return &wrappedSSZObjectEncoder{
		SSZObj: sszObj,
	}
}

func (w *wrappedSSZObjectEncoder) MarshalSSZTo(dst []byte) ([]byte, error) {
	marshalledObj, err := w.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return append(dst, marshalledObj...), nil
}

func (w *wrappedSSZObjectEncoder) MarshalSSZ() ([]byte, error) {
	var buf bytes.Buffer
	if err := w.Serialize(codec.NewEncodingWriter(&buf)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (w *wrappedSSZObjectEncoder) SizeSSZ() int {
	return int(w.SSZObj.ByteLength())
}

func (w *wrappedSSZObjectEncoder) UnmarshalSSZ(b []byte) error {
	return w.Deserialize(codec.NewDecodingReader(bytes.NewReader(b), uint64(len(b))))
}
