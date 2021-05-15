package proj2


import (

	// go get github.com/nweaver/cs161-p2/userlib

	"github.com/nweaver/cs161-p2/userlib"

	"encoding/json"

	"encoding/hex"

	// "go get github.com/google/uuid"
	"github.com/google/uuid"

	"strings"

	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username     string
	Password     string
	Priv         *userlib.PrivateKey
	Signature_Id []byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.


// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	//NOTE: If time allows, store user struct and HMAC as:
	// "users_"||SHA256(Kgen) : IV||E(struct)||HMAC(E(struct))

	//var userdata User

	// 1. Generate RSA key-pair
	Kpriv, _ := userlib.GenerateRSAKey()
	Kpubl := &Kpriv.PublicKey

	//2. Generate Kgen, IV, and signature_id using Argon2 (salt=password).
	//Key length(36) : 16 bytes (key), 16 bytes (IV), 4 bytes (signature -- ID)
	Fields_Generate := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := Fields_Generate[:16]
	IV := Fields_Generate[16:32]
	signature := Fields_Generate[32:]

	// 3. Fill in struct (signature_id should be a random string)
	var userdata = User{Username: username, Password: password, Priv: Kpriv, Signature_Id: signature}

	// 4. Encrypt struct with CFB (key=Kgen, IV=random string)
	// Marshall User before encrypt
	user_, _ := json.Marshal(userdata)

	Encrypted_User := cfb_encrypt(Kgen, user_, IV)

	// 5. Concat IV||E(struct)
	IV_EncryptedStruct := append(IV, Encrypted_User...)

	// 6. Put "signatures_"||signature_id -> HMAC(K_gen, IV||E(struct) into DataStore
	user_data_store := "signatures_" + string(signature[:])
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	userlib.DatastoreSet(user_data_store, expectedMAC)

	// 7. Put "users_"||SHA256(Kgen) -> IV||E(struct) into DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	userlib.DatastoreSet(user_lookup_id, IV_EncryptedStruct)

	// 8. Store RSA public key into KeyStore
	userlib.KeystoreSet(username, *Kpubl)

	// 9. Return pointer to the struct
	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// 1. Reconstruct Kgen using Argon2
	bytes_generated := userlib.Argon2Key([]byte(password), []byte(username), 36)
	Kgen := bytes_generated[:16]

	// 2. Look up "users_"||SHA256(Kgen) in the DataStore and get the E(struct)||IV
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(Kgen))
	user_lookup_id := "users_" + string(sha256.Sum(nil))
	IV_EncryptedStruct, ok := userlib.DatastoreGet(user_lookup_id)

	// 3. If the id is not found in the DataStore, fail with an error
	if !ok {
		return nil, errors.New("Incorrect username or password.")
	}

	// 4. Break up IV||E(struct) and decrypt the structure using Kgen
	IV := IV_EncryptedStruct[:16]
	E_struct := IV_EncryptedStruct[16:]

	//Decrypt then unmarshall data then get ID field
	struct_marshall := cfb_decrypt(Kgen, E_struct, IV)
	var userStruct User
	json.Unmarshal(struct_marshall, &userStruct)

	// 5. Look up "signatures_"||struct->signature_id from the DataStore and
	// get the Signature_HMAC
	id := userStruct.Signature_Id
	id_to_lookup := "signatures_" + string(id)
	signature_hmac, ok := userlib.DatastoreGet(id_to_lookup)

	if !ok {
		return nil, errors.New("HMAC was not found")
	}

	// 6. Verify that HMAC(K_gen, IV||E(struct)) == Signature_HMAC and if not,
	// fail with an error
	mac := userlib.NewHMAC(Kgen)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)

	// Not sure if this is right way to compare but cannot compare using bytes.equals since cannnot import anything else

	if !userlib.Equal(expectedMAC, signature_hmac) {
		//if string(expectedMAC) != string(signature_hmac) {
		return nil, errors.New("Found corrupted data")
	}

	// 7. Check that username == struct->username and password == struct->password,
	// and if not, fail with an error
	if userStruct.Username != username {
		return nil, errors.New("Wrong username")
	}

	// 8. Return a pointer to the user struct
	return &userStruct, err
}

type File struct {
	Data              []byte
	OtherFiles        []string
	Shared_With_Users []string
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// Prepare metadata
	Fields_Generate := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	KgenF := Fields_Generate[:16]
	IV := Fields_Generate[16:32]

	// Call _StoreFileHelper()
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(KgenF))
	fileLookupID := "files_" + string(sha256.Sum(nil))
	(userdata)._StoreFileHelper(fileLookupID, KgenF, IV, data)
}

func (userdata *User) _StoreFileHelper(lookupID string, KgenF []byte, IV []byte, data []byte) {
	// 1. Fill in a File struct with the data, count integer, & users shared with.
	var users_shared []string
	var otherFiles []string
	var fileStruct = File{Data: data, OtherFiles: otherFiles, Shared_With_Users: users_shared}

	// 3. Marshall and encrypt struct with CFB (key=Kgen, IV=random string).
	file_, _ := json.Marshal(fileStruct)
	Encrypted_file := cfb_encrypt(KgenF, file_, IV)

	// 4. Concat IV||E(struct)
	IV_EncryptedStruct := append(IV, Encrypted_file...)

	// 5. Put "files_"||SHA256(KgenF) -> IV||E(struct)||HMAC(K_genF, IV||E(struct)) into DataStore
	mac := userlib.NewHMAC(KgenF)
	mac.Write(IV_EncryptedStruct)
	expectedMAC := mac.Sum(nil)
	IV_EncFile_HMAC := append(IV_EncryptedStruct, expectedMAC...)
	userlib.DatastoreSet(lookupID, IV_EncFile_HMAC)
}

func (userdata *User) _ModifyFileHelper(lookupID string, KgenF []byte, IV []byte, fileStruct *File, newChunkLookupID string) {
	// 1. Fill in a File struct with the data, count integer, & users shared with.
	otherFiles := fileStruct.OtherFiles
	otherFiles = append(otherFiles, newChunkLookupID)
	var newFileStruct = File{
		Data:              fileStruct.Data,
		OtherFiles:        otherFiles,
		Shared_With_Users: fileStruct.Shared_With_Users,
	}

	// 3. Marshall and encrypt struct with CFB (key=Kgen, IV=random string).
	file, _ := json.Marshal(newFileStruct)
	encryptedFile := cfb_encrypt(KgenF, file, IV)

	// 4. Concat IV||E(struct)
	IVAndEncryptedFile := append(IV, encryptedFile...)

	// 5. Put "files_"||SHA256(KgenF) -> IV||E(struct)||HMAC(K_genF, IV||E(struct)) into DataStore
	mac := userlib.NewHMAC(KgenF)
	mac.Write(IVAndEncryptedFile)
	expectedMAC := mac.Sum(nil)
	IVAndEncryptedFileAndHMAC := append(IVAndEncryptedFile, expectedMAC...)
	userlib.DatastoreDelete(lookupID)
	userlib.DatastoreSet(lookupID, IVAndEncryptedFileAndHMAC)
}

func (userdata *User) _ModifyWhenSharingFileHelper(lookupID string, KgenF []byte, IV []byte, fileStruct *File, newUserLookupID string) {
	// 1. Fill in a File struct with the data, count integer, & users shared with.
	otherUsers := fileStruct.Shared_With_Users
	otherUsers = append(otherUsers, newUserLookupID)
	var newFileStruct = File{
		Data:              fileStruct.Data,
		OtherFiles:        fileStruct.OtherFiles,
		Shared_With_Users: otherUsers,
	}

	// 3. Marshall and encrypt struct with CFB (key=Kgen, IV=random string).
	file, _ := json.Marshal(newFileStruct)
	encryptedFile := cfb_encrypt(KgenF, file, IV)

	// 4. Concat IV||E(struct)
	IVAndEncryptedFile := append(IV, encryptedFile...)

	// 5. Put "files_"||SHA256(KgenF) -> IV||E(struct)||HMAC(K_genF, IV||E(struct)) into DataStore
	mac := userlib.NewHMAC(KgenF)
	mac.Write(IVAndEncryptedFile)
	expectedMAC := mac.Sum(nil)
	IVAndEncryptedFileAndHMAC := append(IVAndEncryptedFile, expectedMAC...)
	userlib.DatastoreDelete(lookupID)
	userlib.DatastoreSet(lookupID, IVAndEncryptedFileAndHMAC)
}

func (userdata *User) _GetAndVerifyFile(lookupID string, KgenF []byte, IV []byte) (filePtr *File, newKgenF []byte, newFileIV []byte, err error) {
	// 2. Get and decrypt the File struct from DataStore
	// (NOTE: first look for it in the namespace "shared_files_". Do the
	//	conversion if found, otherwise look at the "files_" namespace)
	// 2.1. Look up the file in the "shared_files_" namespace
	encryptedSharingRecordWithIVAndHMAC, ok := userlib.DatastoreGet("shared_files_" + lookupID)

	// 2.2. If found, do conversion. That is, get the actual, REAL file.
	if ok {
		// Decrypt the sharing record
		size := len(encryptedSharingRecordWithIVAndHMAC)
		encryptedSharingRecordWithIV := encryptedSharingRecordWithIVAndHMAC[:size-32]
		sharingRecordIV := encryptedSharingRecordWithIV[:16]
		encryptedSharingRecord := encryptedSharingRecordWithIV[16:]
		marshalledSharingRecord := cfb_decrypt(KgenF, encryptedSharingRecord, IV)
		var sharingRecordStruct sharingRecord
		json.Unmarshal(marshalledSharingRecord, &sharingRecordStruct)

		if !userlib.Equal(IV, sharingRecordIV) {
			var dummyBytes []byte
			return nil, dummyBytes, dummyBytes, errors.New("IVs are not the same")
		}

		// Return an error if the sharing record struct has been tampered with (check
		// signature and HMAC)
		sharingRecordHMAC := encryptedSharingRecordWithIVAndHMAC[size-32:]
		mac := userlib.NewHMAC(KgenF)
		mac.Write(encryptedSharingRecordWithIV)
		expectedMAC := mac.Sum(nil)

		if !userlib.Equal(expectedMAC, sharingRecordHMAC) {
			// File integrity was compromised!
			var dummyBytes []byte
			return nil, dummyBytes, dummyBytes, errors.New("An integrity error occurred during the shared file conversion")
		}

		// Get the realKgenF and realIV
		KgenF = sharingRecordStruct.FileKey
		IV = sharingRecordStruct.IV

		// Make the realFileLookupID from the realKgenF
		sha256 := userlib.NewSHA256()
		sha256.Write([]byte(KgenF))
		lookupID = string(sha256.Sum(nil))
	}

	// 2.3. Look the file up in the "files_" namespace.
	fileLookupID := "files_" + lookupID
	encryptedFileWithIVAndHMAC, ok := userlib.DatastoreGet(fileLookupID)

	if !ok {
		var dummyBytes []byte
		return nil, dummyBytes, dummyBytes, errors.New("File does not exist with ID " + lookupID)
	}

	// 2.4. Break down the structure
	size := len(encryptedFileWithIVAndHMAC)
	fileStuctHMAC := encryptedFileWithIVAndHMAC[size-32 : size]
	encryptedFileStructWithIV := encryptedFileWithIVAndHMAC[:size-32]

	// 2.5. Decrypt and unmarshall the file
	fileIV := encryptedFileStructWithIV[:16]
	encryptedFileStruct := encryptedFileStructWithIV[16:]
	marshalledFileStruct := cfb_decrypt(KgenF, encryptedFileStruct, fileIV)
	var fileStruct File
	json.Unmarshal(marshalledFileStruct, &fileStruct)

	// 3. Return an error if the file struct has been tampered with (check
	// signature and HMAC) [Optional check]
	mac := userlib.NewHMAC(KgenF)
	mac.Write(encryptedFileStructWithIV)
	expectedMAC := mac.Sum(nil)

	if !userlib.Equal(expectedMAC, fileStuctHMAC) {
		// File integrity was compromised!
		var dummyBytes []byte
		return nil, dummyBytes, dummyBytes, errors.New("An integrity error occurred")
	}

	return &fileStruct, KgenF, IV, err
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	// 1. Reconstruct KgenF using Argon2
	output := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	KgenF := output[:16]
	fileIV := output[16:32]

	// 2. Get and verify the file structure from DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(KgenF))
	lookupID := string(sha256.Sum(nil))
	fileStruct, newKgenF, newFileIV, err := (userdata)._GetAndVerifyFile(lookupID, KgenF, fileIV)

	// 3. Check no errors occurred
	if err != nil {
		return err
	}

	// 4. Store the new file chunk in DataStore
	// (with some random bytes added in the creation of the key)
	newChunkLookupID := uuid.New().String()
	(userdata)._StoreFileHelper("files_"+newChunkLookupID, newKgenF, newFileIV, data)

	// 5. Make this file chunk be connected to the end of the file chunk list.
	sha256 = userlib.NewSHA256()
	sha256.Write([]byte(newKgenF))
	realFileLookupID := string(sha256.Sum(nil))
	(userdata)._ModifyFileHelper("files_"+realFileLookupID, newKgenF, newFileIV, fileStruct, newChunkLookupID)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	// 1. Reconstruct KgenF and IV using Argon2
	output := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	KgenF := output[:16]
	IV := output[16:]

	// 2. Get and verify the file structure from DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(KgenF))
	lookupID := string(sha256.Sum(nil))
	fileStruct, newKgenF, newFileIV, err := (userdata)._GetAndVerifyFile(lookupID, KgenF, IV)

	// 3. Return nil if record not found or has been tampered with
	if err != nil {
		var dummyData []byte
		return dummyData, err
	}

	// 4. Add the first chunk of data to allData
	var allData []byte
	allData = append(allData, (fileStruct).Data...)

	// 5. Add the other chunks of data to allData
	// (while verifying the chunk exists and the integrity is preserved)
	var chunk *File
	for i := 0; i < len(fileStruct.OtherFiles); i++ {
		chunk, _, _, err = (userdata)._GetAndVerifyFile(fileStruct.OtherFiles[i], newKgenF, newFileIV)
		if err != nil {
			var dummyData []byte
			return dummyData, errors.New("AppendError: " + err.Error())
		}
		allData = append(allData, chunk.Data...)
	}

	// 6. Return all the data
	return allData, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Recipient string
	FileKey   []byte
	IV        []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	// 1. Reconstruct KgenF and IV using Argon2 (using index = 0)
	// 1.5. Get the file and error if File struct is not found on the DataStore
	// (NOTE: first look for it in the namespace "shared_files_". Do the
	//	conversion if found, otherwise look at the "files_" namespace)
	// 1.75. Error if data has been tampered with [NOTE: not sure if we need to
	// check this -- prompt doesn't say anything about it]

	// 1. Reconstruct KgenF and IV using Argon2
	output := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	KgenF := output[:16]
	IV := output[16:32]

	// 1.50. Get and verify the file structure from DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(KgenF))
	lookupID := string(sha256.Sum(nil))
	_, newKgenF, newFileIV, err := (userdata)._GetAndVerifyFile(lookupID, KgenF, IV)

	// 1.75. Return nil if record not found or has been tampered with
	if err != nil {
		var dummy string
		return dummy, err
	}

	// 2. Make a sharingRecord struct with the sender's username, receiver's
	// username, KgenF (as FileKey), and IV (make signature_id be empty)
	var sharingRecordStruct sharingRecord
	sharingRecordStruct.Recipient = recipient
	sharingRecordStruct.FileKey = newKgenF
	sharingRecordStruct.IV = newFileIV

	// 3. Look up the RSA Public Key of the recipient in the KeyStore
	// 5. RSA Encrypt the marshalled version of the sharingRecord struct using
	// the recipient's RSA Public Key
	recipientPublicKey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		var dummy string
		return dummy, err
	}
	marshalledStruct, _ := json.Marshal(sharingRecordStruct)
	encryptedStruct, err := userlib.RSAEncrypt(&recipientPublicKey, marshalledStruct, []byte(""))
	if err != nil {
		var dummy string
		return dummy, errors.New("An error occurred")
	}

	// 6. Sign (HMAC) the recipient's username using the current user's RSA
	// private key
	signature, err := userlib.RSASign(userdata.Priv, []byte(recipient))
	if err != nil {
		var dummy string
		return dummy, errors.New("An error occurred while signing with RSA")
	}


	// Store a random byte onto the DataStore with id:
	// "pending_shares_"||random_string
	// (This will be used to verify that the file wasn't already received)
	temporaryKey := uuid.New().String()
	signatureAndEncryptedStruct := append(signature, encryptedStruct...)
	userlib.DatastoreSet("pending_shares_"+temporaryKey, signatureAndEncryptedStruct)
	return temporaryKey, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {

	// 1. Get the encrypted structure
	oneTimeVerificationID := "pending_shares_" + msgid
	signatureAndRSAEncryptedStruct, ok := userlib.DatastoreGet(oneTimeVerificationID)
	if !ok {
		return errors.New("Could not find the encrypted content in the DataStore")
	}

	// 2. Delete "pending_shares_"||SHA256(one_time_verification_id) from the
	// DataStore to prevent message reuses
	userlib.DatastoreDelete(oneTimeVerificationID)

	// Now check the signature
	publicKey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return errors.New("Public Key for user not found")
	}

	signature := signatureAndRSAEncryptedStruct[:256]
	err := userlib.RSAVerify(&publicKey, []byte(userdata.Username), []byte(signature))
	if err != nil {
		return errors.New("Error while verifying the message")
	}

	// 3. Now check decrypt the structure
	RSAEncryptedStruct := signatureAndRSAEncryptedStruct[256:]
	marshalledDecryptedStruct, err := userlib.RSADecrypt(userdata.Priv, []byte(RSAEncryptedStruct), []byte(""))
	if err != nil {
		return errors.New("Error while decrypting the message")
	}

	// 4. Generate NewKgenF and IV using Argon2 with parameters
	output := userlib.Argon2Key([]byte(userdata.Username), []byte(filename), 32)
	NewKgenF := output[:16]
	NewFileIV := output[16:]

	// 5. Concat IV||E(struct)||HMAC(K_genF, IV||E(struct))
	marshalledEncryptedStruct := cfb_encrypt(NewKgenF, marshalledDecryptedStruct, NewFileIV)
	IVAndEncryptedSharingStruct := append(NewFileIV, marshalledEncryptedStruct...)
	mac := userlib.NewHMAC(NewKgenF)
	mac.Write(IVAndEncryptedSharingStruct)
	HMAC := mac.Sum(nil)
	IVAndEncryptedSharingStructAndMAC := append(IVAndEncryptedSharingStruct, HMAC...)

	// 6. Put "shared_files_"||SHA256(NewKgenF) ->
	// IV||E(struct)||HMAC(NewKgenF, IV||E(struct)) into DataStore
	sha256 := userlib.NewSHA256()
	sha256.Write([]byte(NewKgenF))
	sharedFileLookupID := string(sha256.Sum(nil))
	userlib.DatastoreSet("shared_files_"+sharedFileLookupID, IVAndEncryptedSharingStructAndMAC)
	/////

	// 7. Get the original File struct from DataStore (Get
	// "files_"||SHA256(struct->File_Key) and decrypt it with struct->File_Key)
	// [NOTE: this may be insecure because receiver could store the
	// struct->File_Key somewhere! -- let's ask Piazza]
	var decryptedSharingStruct sharingRecord
	json.Unmarshal(marshalledDecryptedStruct, &decryptedSharingStruct)
	sha256 = userlib.NewSHA256()
	sha256.Write([]byte(decryptedSharingStruct.FileKey))
	originalFileLookupID := string(sha256.Sum(nil))
	realFileStruct, realKgenF, realFileIV, err := userdata._GetAndVerifyFile(
		originalFileLookupID,
		decryptedSharingStruct.FileKey,
		decryptedSharingStruct.IV,
	)
	if err != nil {
		return errors.New("Could not find the file being shared")
	}

	// 7.5. Check that the user is supposed to receive this file.
	if userdata.Username != decryptedSharingStruct.Recipient {
		return errors.New("You're not supposed to receive this file")
	}

	// 8. Append the SHA256(NewKGenF) to original File struct's property
	// Shared_With_Users (this will be used for revoking)
	// 9. Update the Original File Struct on the DataStore (marshall and encrypt
	// and store as struct->Iv||E(struct))
	sha256 = userlib.NewSHA256()
	sha256.Write([]byte(realKgenF))
	realFileLookupID := string(sha256.Sum(nil))
	(userdata)._ModifyWhenSharingFileHelper(
		"files_"+realFileLookupID,
		realKgenF,
		realFileIV,
		realFileStruct,
		sharedFileLookupID,
	)

	return nil
}


//-------- helper functions --------//

func cfb_encrypt(key []byte, plainText []byte, iv []byte) (cipherText []byte) {
	stream := userlib.CFBEncrypter(key, iv)
	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)
	return
}

func cfb_decrypt(key []byte, ciphertext []byte, iv []byte) (plaintext []byte) {
	stream := userlib.CFBDecrypter(key, iv)
	plaintext = make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return
}
