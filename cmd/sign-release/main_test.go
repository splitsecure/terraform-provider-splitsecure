package main

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	openpgpv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/openpgp/v1"
)

func TestSignaturePacket_UnwrapsSignResult(t *testing.T) {
	t.Parallel()

	packet := []byte{0x89, 0x02, 0x33, 0x04}

	encoded, err := proto.Marshal(&openpgpv1.SignResult{SignaturePacket: packet})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := signaturePacket(encoded)
	if err != nil {
		t.Fatalf("signaturePacket: %v", err)
	}

	if !bytes.Equal(got, packet) {
		t.Errorf("packet = %x, want %x", got, packet)
	}
}

func TestSignaturePacket_RejectsEmptyResult(t *testing.T) {
	t.Parallel()

	_, err := signaturePacket(nil)
	if !errors.Is(err, errNoSignature) {
		t.Fatalf("err = %v, want errNoSignature", err)
	}
}
