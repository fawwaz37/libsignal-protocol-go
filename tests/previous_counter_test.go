package tests

import (
	"context"
	"testing"

	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
)

// TestPreviousCounterAfterRatchet checks that after a DH ratchet step the
// previous counter on the wire is the last counter of the previous sending
// chain (libsignal: max(index-1, 0)), and never wraps around to 2^32-1.
func TestPreviousCounterAfterRatchet(t *testing.T) {
	ctx := context.Background()
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	bundle := prekey.NewBundle(
		bob.registrationID, bob.deviceID,
		bob.preKeys[0].ID(), bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)
	if err := alice.sessionBuilder.ProcessBundle(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// send encrypts a message and parses it back as the receiver sees it.
	send := func(c *session.Cipher) *protocol.SignalMessage {
		t.Helper()
		ct, err := c.Encrypt(ctx, []byte("hi"))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := protocol.NewSignalMessageFromBytes(ct.Serialize(), serializer.SignalMessage)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	// Alice -> Bob prekey message sets up Bob's session.
	ct, err := aliceCipher.Encrypt(ctx, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(ct.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bobCipher.DecryptMessage(ctx, preKeyMsg); err != nil {
		t.Fatal(err)
	}

	// Bob sent nothing on his previous chain (index 0): counter must be 0.
	bobMsgs := []*protocol.SignalMessage{send(bobCipher), send(bobCipher), send(bobCipher)}
	if pc := bobMsgs[0].Structure().PreviousCounter; pc != 0 {
		t.Errorf("first reply: previous counter = %d, want 0", pc)
	}
	for _, m := range bobMsgs {
		if _, err = aliceCipher.Decrypt(ctx, m); err != nil {
			t.Fatal(err)
		}
	}

	// Alice ratchets; Bob's previous chain carried counters 0..2: counter must be 2.
	if _, err = bobCipher.Decrypt(ctx, send(aliceCipher)); err != nil {
		t.Fatal(err)
	}
	if pc := send(bobCipher).Structure().PreviousCounter; pc != 2 {
		t.Errorf("after ratchet: previous counter = %d, want 2", pc)
	}
}
