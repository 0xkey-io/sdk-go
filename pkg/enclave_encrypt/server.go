package enclave_encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cloudflare/circl/kem"
)

type EnclaveEncryptServer struct {
	enclaveAuthKey *ecdsa.PrivateKey
	targetPrivate  kem.PrivateKey
	organizationId string
	userId         *string
}

type EnclaveEncryptServerRecv struct {
	targetPrivate kem.PrivateKey
}

func NewEnclaveEncryptServer(enclaveAuthKey *ecdsa.PrivateKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	_, targetPrivate, err := KemId.Scheme().GenerateKeyPair()
	if err != nil {
		return EnclaveEncryptServer{}, err
	}

	return EnclaveEncryptServer{
		enclaveAuthKey: enclaveAuthKey,
		targetPrivate:  targetPrivate,
		organizationId: organizationId,
		userId:         userId,
	}, nil
}

func NewEnclaveEncryptServerFromTargetKey(enclaveAuthKey *ecdsa.PrivateKey, targetPrivateKey *kem.PrivateKey, organizationId string, userId *string) (EnclaveEncryptServer, error) {
	return EnclaveEncryptServer{
		enclaveAuthKey: enclaveAuthKey,
		targetPrivate:  *targetPrivateKey,
		organizationId: organizationId,
		userId:         userId,
	}, nil
}

func (s *EnclaveEncryptServer) Encrypt(clientTarget []byte, plaintext []byte) (*ServerSendMsgV1, error) {
	clientTargetKem, err := KemId.Scheme().UnmarshalBinaryPublicKey(clientTarget)
	if err != nil {
		return nil, err
	}

	ciphertext, encappedPublic, err := sealToTarget(&clientTargetKem, plaintext)
	if err != nil {
		return nil, err
	}

	data := ServerSendData{
		EncappedPublic: encappedPublic,
		Ciphertext:     ciphertext,
		OrganizationId: s.organizationId,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	dataSignature, err := P256Sign(s.enclaveAuthKey, dataBytes)
	if err != nil {
		return nil, err
	}

	enclaveQuorumPublic := s.enclaveAuthKey.PublicKey
	//nolint:staticcheck
	enclaveQuorumPublicBytes := elliptic.Marshal(elliptic.P256(), enclaveQuorumPublic.X, enclaveQuorumPublic.Y)

	return &ServerSendMsgV1{
		Version:             DataVersion,
		Data:                dataBytes,
		DataSignature:       dataSignature,
		EnclaveQuorumPublic: enclaveQuorumPublicBytes,
	}, nil
}

func (s *EnclaveEncryptServer) PublishTarget() (*ServerTargetMsgV1, error) {
	targetPublic, err := s.targetPrivate.Public().MarshalBinary()
	if err != nil {
		return nil, err
	}

	data := ServerTargetData{
		TargetPublic:   targetPublic,
		OrganizationId: s.organizationId,
		UserId:         *s.userId,
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	dataSignature, err := P256Sign(s.enclaveAuthKey, dataBytes)
	if err != nil {
		return nil, err
	}

	enclaveQuorumPublic := s.enclaveAuthKey.PublicKey
	//nolint:staticcheck
	enclaveQuorumPublicBytes := elliptic.Marshal(elliptic.P256(), enclaveQuorumPublic.X, enclaveQuorumPublic.Y)

	return &ServerTargetMsgV1{
		Version:             DataVersion,
		Data:                dataBytes,
		DataSignature:       dataSignature,
		EnclaveQuorumPublic: enclaveQuorumPublicBytes,
	}, nil
}

func (s *EnclaveEncryptServer) IntoEnclaveServerRecv() EnclaveEncryptServerRecv {
	return EnclaveEncryptServerRecv{targetPrivate: s.targetPrivate}
}

func (s *EnclaveEncryptServer) AuthEncrypt(clientTarget []byte, plaintext []byte) (string, error) {
	clientTargetKem, err := KemId.Scheme().UnmarshalBinaryPublicKey(clientTarget)
	if err != nil {
		return "", err
	}

	ciphertext, encappedPublic, err := sealToTarget(&clientTargetKem, plaintext)
	if err != nil {
		return "", err
	}

	//nolint:staticcheck
	x, y := elliptic.Unmarshal(elliptic.P256(), encappedPublic)
	compressedEncappedPublic := elliptic.MarshalCompressed(elliptic.P256(), x, y)
	payload := append(compressedEncappedPublic, ciphertext...)

	check := checksum(payload)
	payload = append(payload, check[:]...)

	return base58.Encode(payload), nil
}

func (s *EnclaveEncryptServerRecv) Decrypt(msg ClientSendMsg) ([]byte, error) {
	return openFromSender(*msg.EncappedPublic, s.targetPrivate, *msg.Ciphertext)
}
