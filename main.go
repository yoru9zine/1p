package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v2"

	"golang.org/x/crypto/pbkdf2"

	"github.com/spacemonkeygo/openssl"
)

type contents struct {
	Items []*contentsItem
}

type contentsItem struct {
	UUID     string
	Type     string
	Name     string
	URL      string
	Time     float64
	Folder   string
	Strength float64
	Trashed  string
}

type encryptionKeys struct {
	SL3  string
	SL5  string
	List []*encryptionKeyItem
}

func (ek *encryptionKeys) GetItem(level string) *encryptionKeyItem {
	for _, i := range ek.List {
		if i.Level == level {
			return i
		}
	}
	return nil
}

type encryptionKeyItem struct {
	Data       string
	Validation string
	Level      string
	Identifier string
	Iterations int
}

type passwordEntry struct {
	UUID          string
	UpdatedAt     int
	LocationKey   string
	SecurityLevel string
	ContentsHash  string
	Title         string
	Location      string
	Encrypted     string
	TxTimestamp   int
	CreatedAt     int
	TypeNAme      string
}

type decryptedPasswordEntry struct {
	data map[string]interface{}
	User string
	Pass string
}

func ParseDecryptedPasswordEntry(b []byte) (*decryptedPasswordEntry, error) {
	var v map[string]interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	pe := &decryptedPasswordEntry{data: v}
	for _, fl := range v["fields"].([]interface{}) {
		fv := fl.(map[string]interface{})
		switch fv["designation"] {
		case "password":
			pe.Pass = fv["value"].(string)
		case "username":
			pe.User = fv["value"].(string)
		}
	}
	return pe, nil
}

func (d *decryptedPasswordEntry) Password() {
}

type keychainConfig struct {
	Path string
	Pass string
}

type keychain struct {
	conf           *keychainConfig
	Contents       *contents
	EncriptionKeys *encryptionKeys
}

func (kc *keychain) Load() error {
	if err := kc.loadContentsJSON(); err != nil {
		return err
	}
	e, err := kc.loadEnctyptionKeysJSON()
	if err != nil {
		return err
	}
	kc.EncriptionKeys = e
	return nil
}

func (kc *keychain) loadContentsJSON() error {
	b, err := ioutil.ReadFile(kc.conf.Path + "/data/default/contents.js")
	if err != nil {
		return err
	}

	v := [][]interface{}{}
	if err := json.Unmarshal(b, &v); err != nil {
		panic(err)
	}
	c := &contents{}
	for _, i := range v {
		item := &contentsItem{
			UUID:     i[0].(string),
			Type:     i[1].(string),
			Name:     i[2].(string),
			URL:      i[3].(string),
			Time:     i[4].(float64),
			Folder:   i[5].(string),
			Strength: i[6].(float64),
			Trashed:  i[7].(string),
		}
		c.Items = append(c.Items, item)
	}
	kc.Contents = c
	return nil
}

func (kc *keychain) loadEnctyptionKeysJSON() (*encryptionKeys, error) {
	b, err := ioutil.ReadFile(kc.conf.Path + "/data/default/encryptionKeys.js")
	if err != nil {
		return nil, err
	}
	e := &encryptionKeys{}
	if err := json.Unmarshal(b, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (kc *keychain) Find(name string) *contentsItem {
	for _, i := range kc.Contents.Items {
		if i.Name == name {
			return i
		}
	}
	return nil
}
func (kc *keychain) ReadPasswordEntry(uuid string) (*passwordEntry, error) {
	b, err := ioutil.ReadFile(kc.conf.Path + "/data/default/" + uuid + ".1password")
	if err != nil {
		return nil, err
	}
	e := &passwordEntry{}
	if err := json.Unmarshal(b, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (kc *keychain) Decrypt(uuid string) (*decryptedPasswordEntry, error) {
	entry, err := kc.ReadPasswordEntry(uuid)
	if err != nil {
		return nil, err
	}

	keyInfo := kc.EncriptionKeys.GetItem(entry.SecurityLevel)
	encKey := keyInfo.Data
	encPass := entry.Encrypted

	key, err := base64decode(encKey)
	if err != nil {
		return nil, fmt.Errorf("key is not base64: %s", err)
	}

	password, err := base64decode(encPass)
	if err != nil {
		return nil, fmt.Errorf("password is not base64: %s", err)
	}

	keySalt := key[8:16]
	keyData := key[16:]

	derivedKey := pbkdf2.Key([]byte(kc.conf.Pass), keySalt, keyInfo.Iterations, 32, sha1.New)

	// Now we need to extract AES key and IV from newly derived key
	aesKey := derivedKey[0:16]
	aesIv := derivedKey[16:32]
	keyRaw, err := decrypt(keyData, aesKey, aesIv)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt key: %s", err)
	}
	passwordSalt := password[8:16]
	passwordData := password[16:]

	// Now, lets derive AES key and IV from password contents
	passwordKey, passwordIv := deriveKey(keyRaw, passwordSalt)

	// And finally, decrypt password contents
	passwordRaw, err := decrypt(passwordData, passwordKey, passwordIv)
	if err != nil {
		log.Fatalln("unable to decrypt password:", err)
	}

	return ParseDecryptedPasswordEntry(passwordRaw)
}

type Config struct {
	Chains []*keychainConfig
}

func readConfig() (*Config, error) {
	b, err := ioutil.ReadFile(path.Join(os.Getenv("HOME"), ".1prc"))
	if err != nil {
		return nil, err
	}
	var c Config
	err = yaml.Unmarshal(b, &c)
	return &c, err
}

func main() {
	var (
		listMode     = flag.Bool("l", false, "list mode")
		showPassword = flag.Bool("p", false, "show password")
		showUsername = flag.Bool("u", false, "show username")
	)
	flag.Parse()

	conf, err := readConfig()
	if err != nil {
		panic(err)
	}

	keychains := []*keychain{}
	for _, c := range conf.Chains {
		kc := &keychain{conf: c}
		kc.Load()
		keychains = append(keychains, kc)
	}
	if *listMode {
		for _, kc := range keychains {
			for _, item := range kc.Contents.Items {
				fmt.Println(item.Name)
			}
		}
		return
	}
	name := flag.Arg(0)

	var entry *decryptedPasswordEntry
	for _, kc := range keychains {
		e := kc.Find(name)
		if e == nil {
			continue
		}
		var err error
		entry, err = kc.Decrypt(e.UUID)
		if err != nil {
			continue
		}
	}

	if entry == nil {
		return
	}

	if *showUsername {
		fmt.Printf("%s", entry.User)
		return
	}
	if *showPassword {
		fmt.Printf("%s", entry.Pass)
		return
	}

}

func decrypt(data, key, iv []byte) ([]byte, error) {
	cipher, err := openssl.GetCipherByName("aes-128-cbc")
	if err != nil {
		return nil, err
	}

	ctx, err := openssl.NewDecryptionCipherCtx(cipher, nil, key, iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.DecryptUpdate(data)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.DecryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}

func deriveKey(password []byte, salt []byte) (key []byte, iv []byte) {
	rounds := 2
	data := append(password, salt...)
	md5Hashes := make([][]byte, rounds)
	sum := md5.Sum(data)

	md5Hashes[0] = append([]byte{}, sum[:]...)

	for i := 1; i < rounds; i++ {
		sum = md5.Sum(append(md5Hashes[i-1], data...))
		md5Hashes[i] = append([]byte{}, sum[:]...)
	}

	return md5Hashes[0], md5Hashes[1]
}

func base64decode(data string) ([]byte, error) {
	sanitized := strings.Replace(data, `\`, "", -1)
	return base64.StdEncoding.DecodeString(sanitized)
}
